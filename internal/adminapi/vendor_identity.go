package adminapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
	"github.com/yourorg/aegisnas-pi4/internal/vendoridentity"
)

const (
	vendorIdentityPreviewTTL      = 15 * time.Minute
	defaultLegacyAcceptance       = 7 * 24 * time.Hour
	maximumLegacyAcceptance       = 30 * 24 * time.Hour
	vendorIdentityRollbackPrefix  = "ROLLBACK "
	vendorIdentityMigrationIDSize = 16
	vendorIdentityTokenSize       = 32
)

var (
	vendorIdentityMigrationMu sync.Mutex
	vendorIdentityNow         = time.Now
	fetchVendorAssignmentFn   = func(ctx context.Context, pen int, organization string) (vendoridentity.AssignmentEvidence, error) {
		return vendoridentity.NewFetcher().Fetch(ctx, pen, organization)
	}
	applyVendorIdentityRadiusFn = radius.ApplyVendorIdentityConfig
)

type vendorIdentitySnapshot struct {
	Name                     string `json:"name"`
	PEN                      int    `json:"pen"`
	IdentityMode             string `json:"identity_mode"`
	AssignedOrganization     string `json:"assigned_organization,omitempty"`
	AssignmentRegistryURL    string `json:"assignment_registry_url,omitempty"`
	RegistryLastUpdated      string `json:"registry_last_updated,omitempty"`
	AssignmentVerifiedAt     string `json:"assignment_verified_at,omitempty"`
	AssignmentRegistrySHA256 string `json:"assignment_registry_sha256,omitempty"`
	AssignmentRecordSHA256   string `json:"assignment_record_sha256,omitempty"`
	LegacyPENs               []int  `json:"legacy_pens,omitempty"`
	LegacyAcceptUntil        string `json:"legacy_accept_until,omitempty"`
}

type vendorIdentityPreviewRequest struct {
	PEN                   int    `json:"pen"`
	ExpectedOrganization  string `json:"expected_organization"`
	LegacyAcceptanceHours *int   `json:"legacy_acceptance_hours,omitempty"`
}

type vendorIdentityApplyRequest struct {
	MigrationID       string `json:"migration_id"`
	ConfirmationToken string `json:"confirmation_token"`
}

type vendorIdentityRollbackRequest struct {
	ConfirmationText string `json:"confirmation_text"`
}

type vendorIdentityPreviewResponse struct {
	MigrationID       string                            `json:"migration_id"`
	ConfirmationToken string                            `json:"confirmation_token"`
	ExpiresAt         time.Time                         `json:"expires_at"`
	Current           vendorIdentitySnapshot            `json:"current"`
	Target            vendorIdentitySnapshot            `json:"target"`
	Evidence          vendoridentity.AssignmentEvidence `json:"evidence"`
	ActiveSessions    int                               `json:"active_sessions"`
	AffectedSystems   []string                          `json:"affected_systems"`
	Warnings          []string                          `json:"warnings"`
	RestartRequired   bool                              `json:"restart_required"`
}

type vendorIdentityStatusResponse struct {
	Status              string                             `json:"status"`
	Ready               bool                               `json:"ready"`
	Current             vendorIdentitySnapshot             `json:"current"`
	Assignment          *db.VendorIdentityAssignment       `json:"assignment,omitempty"`
	Evidence            *vendoridentity.AssignmentEvidence `json:"evidence,omitempty"`
	ConfigEvidenceValid bool                               `json:"config_evidence_valid"`
	LegacyWindowActive  bool                               `json:"legacy_window_active"`
	Migrations          []db.VendorIdentityMigration       `json:"migrations"`
	Metrics             db.VendorIdentityMigrationMetrics  `json:"metrics"`
	Warnings            []string                           `json:"warnings,omitempty"`
}

func HandleGetVendorIdentity(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if cfg == nil {
		writeVendorIdentityError(w, http.StatusServiceUnavailable, "config_unavailable", "configuration is not loaded")
		return
	}
	if db.DB == nil {
		writeVendorIdentityError(w, http.StatusServiceUnavailable, "database_unavailable", "database is not initialized")
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			writeVendorIdentityError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 500")
			return
		}
		limit = parsed
	}
	migrations, err := db.ListVendorIdentityMigrations(db.DB, limit)
	if err != nil {
		writeVendorIdentityError(w, http.StatusInternalServerError, "history_unavailable", err.Error())
		return
	}
	assignment, err := db.ActiveVendorIdentityAssignment(db.DB)
	if err != nil {
		writeVendorIdentityError(w, http.StatusInternalServerError, "assignment_unavailable", err.Error())
		return
	}
	metrics, err := db.VendorIdentityMetrics(db.DB)
	if err != nil {
		writeVendorIdentityError(w, http.StatusInternalServerError, "metrics_unavailable", err.Error())
		return
	}

	current := snapshotVendorIdentity(cfg.Radius.Vendor)
	response := vendorIdentityStatusResponse{
		Status:     "lab",
		Current:    current,
		Assignment: assignment,
		Migrations: migrations,
		Metrics:    metrics,
	}
	if evidence, evidenceErr := config.RadiusVendorAssignmentEvidence(cfg.Radius.Vendor); evidenceErr == nil {
		response.Evidence = &evidence
		response.ConfigEvidenceValid = evidence.Validate(cfg.Radius.Vendor.ID, cfg.Radius.Vendor.AssignedOrganization) == nil
	}
	response.LegacyWindowActive = len(radius.ProductVendorInboundIDsAt(cfg.Radius.Vendor, vendorIdentityNow())) > 1

	switch strings.ToLower(strings.TrimSpace(cfg.Radius.Vendor.IdentityMode)) {
	case "production":
		response.Status = "production_unverified"
		if assignment != nil && assignment.PEN == uint32(cfg.Radius.Vendor.ID) && response.ConfigEvidenceValid && assignment.RecordSHA256 == cfg.Radius.Vendor.AssignmentRecordSHA {
			response.Status = "production_verified"
			response.Ready = true
		} else {
			response.Warnings = append(response.Warnings, "The production identity config does not match an active verified assignment record.")
		}
	case "unverified":
		response.Status = "unverified"
		response.Warnings = append(response.Warnings, "A non-placeholder PEN is configured without verified IANA evidence.")
	default:
		response.Warnings = append(response.Warnings, "The lab PEN must not be used for production vendor-specific attributes.")
	}
	for _, migration := range migrations {
		if migration.Status == "applying" {
			response.Warnings = append(response.Warnings, "Migration "+migration.ID+" was interrupted while applying and requires operator recovery.")
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func HandlePreviewVendorIdentityMigration(w http.ResponseWriter, r *http.Request) {
	var request vendorIdentityPreviewRequest
	if err := decodeVendorIdentityBody(w, r, &request); err != nil {
		writeVendorIdentityError(w, http.StatusBadRequest, "invalid_request", "request body must be valid JSON")
		return
	}
	if err := vendoridentity.ValidateProductionPEN(request.PEN); err != nil {
		writeVendorIdentityError(w, http.StatusBadRequest, "invalid_pen", err.Error())
		return
	}
	request.ExpectedOrganization = strings.Join(strings.Fields(request.ExpectedOrganization), " ")
	if request.ExpectedOrganization == "" || len(request.ExpectedOrganization) > 255 {
		writeVendorIdentityError(w, http.StatusBadRequest, "invalid_organization", "expected_organization must contain between 1 and 255 characters")
		return
	}
	legacyDuration := defaultLegacyAcceptance
	if request.LegacyAcceptanceHours != nil {
		if *request.LegacyAcceptanceHours < 0 || time.Duration(*request.LegacyAcceptanceHours)*time.Hour > maximumLegacyAcceptance {
			writeVendorIdentityError(w, http.StatusBadRequest, "invalid_legacy_window", "legacy_acceptance_hours must be between 0 and 720")
			return
		}
		legacyDuration = time.Duration(*request.LegacyAcceptanceHours) * time.Hour
	}

	vendorIdentityMigrationMu.Lock()
	defer vendorIdentityMigrationMu.Unlock()
	cfg := config.Get()
	if cfg == nil || db.DB == nil {
		writeVendorIdentityError(w, http.StatusServiceUnavailable, "service_unavailable", "configuration and database must be initialized")
		return
	}
	evidence, err := fetchVendorAssignmentFn(r.Context(), request.PEN, request.ExpectedOrganization)
	if err != nil {
		writeVendorIdentityError(w, http.StatusUnprocessableEntity, "iana_verification_failed", err.Error())
		return
	}
	if err := evidence.Validate(request.PEN, request.ExpectedOrganization); err != nil {
		writeVendorIdentityError(w, http.StatusUnprocessableEntity, "invalid_evidence", err.Error())
		return
	}
	now := vendorIdentityNow().UTC()
	before := snapshotVendorIdentity(cfg.Radius.Vendor)
	after := before
	after.PEN = request.PEN
	after.IdentityMode = "production"
	after.AssignedOrganization = evidence.Organization
	after.AssignmentRegistryURL = evidence.RegistryURL
	after.RegistryLastUpdated = evidence.RegistryLastUpdated
	after.AssignmentVerifiedAt = evidence.FetchedAt.UTC().Format(time.RFC3339)
	after.AssignmentRegistrySHA256 = evidence.RegistrySHA256
	after.AssignmentRecordSHA256 = evidence.RecordSHA256
	after.LegacyPENs = append([]int(nil), before.LegacyPENs...)
	if legacyDuration > 0 && before.PEN != after.PEN && !containsPEN(after.LegacyPENs, before.PEN) {
		after.LegacyPENs = append(after.LegacyPENs, before.PEN)
	}
	if len(after.LegacyPENs) > 0 && legacyDuration > 0 {
		after.LegacyAcceptUntil = now.Add(legacyDuration).Format(time.RFC3339)
	} else {
		after.LegacyPENs = nil
		after.LegacyAcceptUntil = ""
	}

	candidate := cloneConfigWithVendorSnapshot(cfg, after)
	if err := candidate.Validate(); err != nil {
		writeVendorIdentityError(w, http.StatusUnprocessableEntity, "candidate_invalid", err.Error())
		return
	}
	generated, err := radius.NewGenerator(candidate).Generate()
	if err != nil {
		writeVendorIdentityError(w, http.StatusUnprocessableEntity, "dictionary_generation_failed", err.Error())
		return
	}
	expectedDirective := fmt.Sprintf("VENDOR %s %d", after.Name, after.PEN)
	if !strings.Contains(generated.VendorDictionary, expectedDirective) {
		writeVendorIdentityError(w, http.StatusInternalServerError, "dictionary_mismatch", "generated dictionary does not contain the target vendor directive")
		return
	}

	migrationID, err := randomHex(vendorIdentityMigrationIDSize)
	if err != nil {
		writeVendorIdentityError(w, http.StatusInternalServerError, "entropy_unavailable", err.Error())
		return
	}
	confirmation, err := randomHex(vendorIdentityTokenSize)
	if err != nil {
		writeVendorIdentityError(w, http.StatusInternalServerError, "entropy_unavailable", err.Error())
		return
	}
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	evidenceJSON, _ := json.Marshal(evidence)
	checksum := sha256.Sum256(beforeJSON)
	confirmationDigest := sha256.Sum256([]byte(confirmation))
	expiresAt := now.Add(vendorIdentityPreviewTTL)
	migration := db.VendorIdentityMigration{
		ID: migrationID, Status: "previewed", FromVendorName: before.Name, FromPEN: uint32(before.PEN),
		ToVendorName: after.Name, ToPEN: uint32(after.PEN), Organization: evidence.Organization,
		EvidenceJSON: string(evidenceJSON), BeforeJSON: string(beforeJSON), AfterJSON: string(afterJSON),
		ConfigChecksum: hex.EncodeToString(checksum[:]), ConfirmationSHA256: hex.EncodeToString(confirmationDigest[:]),
		ExpiresAt: expiresAt, CreatedBy: userFromRequest(r), CreatedAt: now,
	}
	if err := db.CreateVendorIdentityMigration(db.DB, migration); err != nil {
		writeVendorIdentityError(w, http.StatusInternalServerError, "preview_persist_failed", err.Error())
		return
	}
	audit(r, "preview_vendor_identity_migration", fmt.Sprintf("migration=%s from_pen=%d to_pen=%d organization=%q", migrationID, before.PEN, after.PEN, evidence.Organization), "previewed")
	writeJSON(w, http.StatusOK, vendorIdentityPreviewResponse{
		MigrationID: migrationID, ConfirmationToken: confirmation, ExpiresAt: expiresAt,
		Current: before, Target: after, Evidence: evidence, ActiveSessions: activeSessionCount(),
		AffectedSystems: []string{"AegisNAS runtime configuration", "FreeRADIUS dictionary.aegisnas", "RADIUS VSA packet encoder and decoder", "vendor compatibility and production-readiness reports", "HA configuration replication"},
		Warnings:        []string{"Update every peer and integration to the assigned PEN.", "Outbound packets switch to the assigned PEN immediately after apply.", "The previous PEN is accepted inbound only until the displayed legacy deadline."},
		RestartRequired: false,
	})
}

func HandleApplyVendorIdentityMigration(w http.ResponseWriter, r *http.Request) {
	var request vendorIdentityApplyRequest
	if err := decodeVendorIdentityBody(w, r, &request); err != nil {
		writeVendorIdentityError(w, http.StatusBadRequest, "invalid_request", "request body must be valid JSON")
		return
	}
	request.MigrationID = strings.TrimSpace(request.MigrationID)
	request.ConfirmationToken = strings.TrimSpace(request.ConfirmationToken)
	if request.MigrationID == "" || request.ConfirmationToken == "" {
		writeVendorIdentityError(w, http.StatusBadRequest, "confirmation_required", "migration_id and confirmation_token are required")
		return
	}

	vendorIdentityMigrationMu.Lock()
	defer vendorIdentityMigrationMu.Unlock()
	migration, err := db.GetVendorIdentityMigration(db.DB, request.MigrationID)
	if err != nil {
		status := http.StatusInternalServerError
		code := "migration_unavailable"
		if errors.Is(err, db.ErrVendorIdentityMigrationNotFound) {
			status, code = http.StatusNotFound, "migration_not_found"
		}
		writeVendorIdentityError(w, status, code, err.Error())
		return
	}
	tokenDigest := sha256.Sum256([]byte(request.ConfirmationToken))
	expectedDigest, err := hex.DecodeString(migration.ConfirmationSHA256)
	if err != nil || subtle.ConstantTimeCompare(tokenDigest[:], expectedDigest) != 1 {
		writeVendorIdentityError(w, http.StatusForbidden, "confirmation_invalid", "confirmation token is invalid")
		return
	}
	now := vendorIdentityNow().UTC()
	if now.After(migration.ExpiresAt) {
		_ = db.FailVendorIdentityMigration(db.DB, migration.ID, "preview expired before apply")
		writeVendorIdentityError(w, http.StatusConflict, "preview_expired", "migration preview has expired; create a new preview")
		return
	}
	cfg := config.Get()
	if cfg == nil {
		writeVendorIdentityError(w, http.StatusServiceUnavailable, "config_unavailable", "configuration is not loaded")
		return
	}
	current := snapshotVendorIdentity(cfg.Radius.Vendor)
	currentJSON, _ := json.Marshal(current)
	currentChecksum := sha256.Sum256(currentJSON)
	if !strings.EqualFold(migration.ConfigChecksum, hex.EncodeToString(currentChecksum[:])) {
		_ = db.FailVendorIdentityMigration(db.DB, migration.ID, "vendor identity changed after preview")
		writeVendorIdentityError(w, http.StatusConflict, "preview_stale", "vendor identity changed after preview; create a new preview")
		return
	}
	var before, after vendorIdentitySnapshot
	var evidence vendoridentity.AssignmentEvidence
	if json.Unmarshal([]byte(migration.BeforeJSON), &before) != nil || json.Unmarshal([]byte(migration.AfterJSON), &after) != nil || json.Unmarshal([]byte(migration.EvidenceJSON), &evidence) != nil {
		writeVendorIdentityError(w, http.StatusInternalServerError, "migration_corrupt", "migration record cannot be decoded")
		return
	}
	if err := evidence.Validate(after.PEN, after.AssignedOrganization); err != nil {
		writeVendorIdentityError(w, http.StatusUnprocessableEntity, "evidence_invalid", err.Error())
		return
	}
	candidate := cloneConfigWithVendorSnapshot(cfg, after)
	if err := candidate.Validate(); err != nil {
		writeVendorIdentityError(w, http.StatusUnprocessableEntity, "candidate_invalid", err.Error())
		return
	}
	if _, err := radius.NewGenerator(candidate).Generate(); err != nil {
		writeVendorIdentityError(w, http.StatusUnprocessableEntity, "candidate_generation_failed", err.Error())
		return
	}
	claimed, err := db.ClaimVendorIdentityMigration(db.DB, migration.ID, now)
	if err != nil || !claimed {
		writeVendorIdentityError(w, http.StatusConflict, "migration_not_claimable", "migration is expired, already used, or not previewed")
		return
	}
	if _, err := config.SaveConfig(candidate); err != nil {
		_ = db.FailVendorIdentityMigration(db.DB, migration.ID, "save config: "+err.Error())
		writeVendorIdentityError(w, http.StatusInternalServerError, "config_save_failed", err.Error())
		return
	}
	if err := applyVendorIdentityRadiusFn(candidate); err != nil {
		recovery := cloneConfigWithVendorSnapshot(candidate, before)
		recoveryErr := restoreVendorIdentityConfig(recovery)
		failure := "FreeRADIUS apply failed: " + err.Error()
		if recoveryErr != nil {
			failure += "; automatic restoration failed: " + recoveryErr.Error()
		}
		_ = db.FailVendorIdentityMigration(db.DB, migration.ID, failure)
		audit(r, "apply_vendor_identity_migration", "migration="+migration.ID, "failed: "+failure)
		writeVendorIdentityError(w, http.StatusInternalServerError, "radius_apply_failed", failure)
		return
	}
	assignment := db.VendorIdentityAssignment{
		PEN: evidence.PEN, VendorName: after.Name, Organization: evidence.Organization,
		RegistryURL: evidence.RegistryURL, RegistryLastUpdated: evidence.RegistryLastUpdated,
		RegistrySHA256: evidence.RegistrySHA256, RecordSHA256: evidence.RecordSHA256,
		EvidenceJSON: migration.EvidenceJSON, VerifiedAt: evidence.FetchedAt,
	}
	if err := db.CompleteVendorIdentityMigration(db.DB, migration, assignment, now); err != nil {
		writeVendorIdentityError(w, http.StatusInternalServerError, "migration_finalize_failed", err.Error())
		return
	}
	audit(r, "apply_vendor_identity_migration", fmt.Sprintf("migration=%s pen=%d organization=%q", migration.ID, after.PEN, after.AssignedOrganization), "applied")
	writeJSON(w, http.StatusOK, map[string]any{"status": "applied", "migration_id": migration.ID, "identity": after, "radius_restarted": true})
}

func HandleRollbackVendorIdentityMigration(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	var request vendorIdentityRollbackRequest
	if err := decodeVendorIdentityBody(w, r, &request); err != nil {
		writeVendorIdentityError(w, http.StatusBadRequest, "invalid_request", "request body must be valid JSON")
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(request.ConfirmationText)), []byte(vendorIdentityRollbackPrefix+id)) != 1 {
		writeVendorIdentityError(w, http.StatusBadRequest, "rollback_confirmation_invalid", "confirmation_text must equal "+vendorIdentityRollbackPrefix+id)
		return
	}

	vendorIdentityMigrationMu.Lock()
	defer vendorIdentityMigrationMu.Unlock()
	migration, err := db.GetVendorIdentityMigration(db.DB, id)
	if err != nil {
		writeVendorIdentityError(w, http.StatusNotFound, "migration_not_found", err.Error())
		return
	}
	if migration.Status != "applied" && migration.Status != "applying" && migration.Status != "failed" {
		writeVendorIdentityError(w, http.StatusConflict, "migration_not_recoverable", "only applied, interrupted, or failed migrations can be rolled back")
		return
	}
	var before, after vendorIdentitySnapshot
	if json.Unmarshal([]byte(migration.BeforeJSON), &before) != nil || json.Unmarshal([]byte(migration.AfterJSON), &after) != nil {
		writeVendorIdentityError(w, http.StatusInternalServerError, "migration_corrupt", "migration snapshots cannot be decoded")
		return
	}
	cfg := config.Get()
	if cfg == nil {
		writeVendorIdentityError(w, http.StatusServiceUnavailable, "config_unavailable", "configuration is not loaded")
		return
	}
	current := snapshotVendorIdentity(cfg.Radius.Vendor)
	if current.PEN != before.PEN {
		recovery := cloneConfigWithVendorSnapshot(cfg, before)
		if _, err := config.SaveConfig(recovery); err != nil {
			writeVendorIdentityError(w, http.StatusInternalServerError, "rollback_save_failed", err.Error())
			return
		}
		if err := applyVendorIdentityRadiusFn(recovery); err != nil {
			_ = restoreVendorIdentityConfig(cloneConfigWithVendorSnapshot(recovery, after))
			writeVendorIdentityError(w, http.StatusInternalServerError, "rollback_radius_failed", err.Error())
			return
		}
	}
	if err := db.RollbackVendorIdentityMigration(db.DB, migration.ID, migration.FromPEN, migration.ToPEN, vendorIdentityNow().UTC()); err != nil {
		writeVendorIdentityError(w, http.StatusInternalServerError, "rollback_finalize_failed", err.Error())
		return
	}
	audit(r, "rollback_vendor_identity_migration", fmt.Sprintf("migration=%s from_pen=%d restored_pen=%d", migration.ID, migration.ToPEN, migration.FromPEN), "rolled_back")
	writeJSON(w, http.StatusOK, map[string]any{"status": "rolled_back", "migration_id": migration.ID, "identity": before, "radius_restarted": true})
}

func snapshotVendorIdentity(vendor config.RadiusVendorConfig) vendorIdentitySnapshot {
	return vendorIdentitySnapshot{
		Name: strings.TrimSpace(vendor.Name), PEN: vendor.ID, IdentityMode: strings.ToLower(strings.TrimSpace(vendor.IdentityMode)),
		AssignedOrganization: strings.TrimSpace(vendor.AssignedOrganization), AssignmentRegistryURL: strings.TrimSpace(vendor.AssignmentRegistryURL),
		RegistryLastUpdated: strings.TrimSpace(vendor.RegistryLastUpdated), AssignmentVerifiedAt: strings.TrimSpace(vendor.AssignmentVerifiedAt),
		AssignmentRegistrySHA256: strings.TrimSpace(vendor.AssignmentRegistrySHA), AssignmentRecordSHA256: strings.TrimSpace(vendor.AssignmentRecordSHA),
		LegacyPENs: append([]int(nil), vendor.LegacyIDs...), LegacyAcceptUntil: strings.TrimSpace(vendor.LegacyAcceptUntil),
	}
}

func cloneConfigWithVendorSnapshot(base *config.Config, snapshot vendorIdentitySnapshot) *config.Config {
	next := *base
	next.Radius = base.Radius
	next.Radius.Vendor = base.Radius.Vendor
	next.Radius.Vendor.Name = snapshot.Name
	next.Radius.Vendor.ID = snapshot.PEN
	next.Radius.Vendor.IdentityMode = snapshot.IdentityMode
	next.Radius.Vendor.AssignedOrganization = snapshot.AssignedOrganization
	next.Radius.Vendor.AssignmentRegistryURL = snapshot.AssignmentRegistryURL
	next.Radius.Vendor.RegistryLastUpdated = snapshot.RegistryLastUpdated
	next.Radius.Vendor.AssignmentVerifiedAt = snapshot.AssignmentVerifiedAt
	next.Radius.Vendor.AssignmentRegistrySHA = snapshot.AssignmentRegistrySHA256
	next.Radius.Vendor.AssignmentRecordSHA = snapshot.AssignmentRecordSHA256
	next.Radius.Vendor.LegacyIDs = append([]int(nil), snapshot.LegacyPENs...)
	next.Radius.Vendor.LegacyAcceptUntil = snapshot.LegacyAcceptUntil
	return &next
}

func restoreVendorIdentityConfig(cfg *config.Config) error {
	if _, err := config.SaveConfig(cfg); err != nil {
		return err
	}
	return applyVendorIdentityRadiusFn(cfg)
}

func containsPEN(values []int, pen int) bool {
	for _, value := range values {
		if value == pen {
			return true
		}
	}
	return false
}

func randomHex(size int) (string, error) {
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		return "", fmt.Errorf("read cryptographic randomness: %w", err)
	}
	return hex.EncodeToString(payload), nil
}

func activeSessionCount() int {
	if db.DB == nil {
		return 0
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE end_time IS NULL`).Scan(&count); err != nil {
		return 0
	}
	return count
}

func writeVendorIdentityError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func decodeVendorIdentityBody(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain one JSON object")
		}
		return err
	}
	return nil
}
