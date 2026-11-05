package adminapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

// Admission receipts are root-managed installation records, not signatures.
// Never turn a local file's claim into a fresh cryptographic verification claim.
type releaseAdmission struct {
	SchemaVersion                int               `json:"schema_version"`
	FeatureID                    string            `json:"feature_id"`
	Status                       string            `json:"status"`
	VerifiedAt                   time.Time         `json:"verified_at"`
	ArtifactSHA256               string            `json:"artifact_sha256"`
	SignatureVerifiedAtAdmission bool              `json:"signature_verified_at_admission"`
	PayloadSHA256                map[string]string `json:"payload_sha256"`
	Manifest                     releaseManifest   `json:"manifest"`
}

type releaseManifest struct {
	SchemaVersion   int    `json:"schema_version"`
	SourceCommit    string `json:"source_commit"`
	Repository      string `json:"repository"`
	Platform        string `json:"platform"`
	ReleaseSequence int64  `json:"release_sequence"`
}

type releaseSecurityReport struct {
	FeatureID                    string           `json:"feature_id"`
	Status                       string           `json:"status"`
	GoVersion                    string           `json:"go_version"`
	SignatureReverified          bool             `json:"signature_reverified"`
	SignatureVerifiedAtAdmission bool             `json:"signature_verified_at_admission"`
	CurrentBinaryMatchesReceipt  bool             `json:"current_binary_matches_receipt"`
	VerifiedAt                   *time.Time       `json:"verified_at,omitempty"`
	ArtifactSHA256               string           `json:"artifact_sha256,omitempty"`
	Release                      *releaseManifest `json:"release,omitempty"`
	Blockers                     []string         `json:"blockers"`
	Scope                        string           `json:"scope"`
}

var releaseDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var releaseCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var releaseRepoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func buildReleaseSecurityReport(directory, executable string, now time.Time) releaseSecurityReport {
	report := releaseSecurityReport{
		FeatureID: "NAS-0116", Status: "not_admitted", GoVersion: runtime.Version(), Blockers: []string{},
		Scope: "Root-managed admission receipt and current API binary only. Attestations are not reverified here; OS, other services and live network certification are outside this report.",
	}
	file, err := os.Open(filepath.Join(directory, "admission.json"))
	if err != nil {
		report.Blockers = append(report.Blockers, "No readable release admission receipt is installed.")
		return report
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4*1024*1024 {
		report.Status = "invalid_receipt"
		report.Blockers = append(report.Blockers, "Admission receipt is invalid or exceeds the size limit.")
		return report
	}
	var receipt releaseAdmission
	decoder := json.NewDecoder(io.LimitReader(file, 4*1024*1024+1))
	err = decoder.Decode(&receipt)
	var extra any
	if err != nil || decoder.Decode(&extra) != io.EOF || receipt.SchemaVersion != 1 ||
		receipt.FeatureID != "NAS-0116" || receipt.Status != "admitted" ||
		!receipt.SignatureVerifiedAtAdmission || !releaseDigestPattern.MatchString(receipt.ArtifactSHA256) ||
		receipt.Manifest.SchemaVersion != 1 || !releaseCommitPattern.MatchString(receipt.Manifest.SourceCommit) ||
		!releaseRepoPattern.MatchString(receipt.Manifest.Repository) || receipt.Manifest.ReleaseSequence < 1 ||
		(receipt.Manifest.Platform != "linux-amd64" && receipt.Manifest.Platform != "linux-arm64") ||
		receipt.VerifiedAt.IsZero() || receipt.VerifiedAt.After(now.Add(5*time.Minute)) {
		report.Status = "invalid_receipt"
		report.Blockers = append(report.Blockers, "Admission receipt is malformed or contains invalid verification metadata.")
		return report
	}
	expected := receipt.PayloadSHA256["bin/"+filepath.Base(executable)]
	if !releaseDigestPattern.MatchString(expected) {
		report.Status = "integrity_mismatch"
		report.Blockers = append(report.Blockers, "Current API binary is absent from the admission manifest.")
		return report
	}
	binary, err := os.Open(executable)
	if err != nil {
		report.Status = "integrity_mismatch"
		report.Blockers = append(report.Blockers, "Current API binary could not be checked.")
		return report
	}
	defer binary.Close()
	hash := sha256.New()
	_, err = io.Copy(hash, binary)
	if err != nil || hex.EncodeToString(hash.Sum(nil)) != expected {
		report.Status = "integrity_mismatch"
		report.Blockers = append(report.Blockers, "Current API binary differs from the admitted payload.")
		return report
	}
	report.Status = "admission_recorded"
	report.CurrentBinaryMatchesReceipt = true
	report.SignatureVerifiedAtAdmission = true
	report.VerifiedAt = &receipt.VerifiedAt
	report.ArtifactSHA256 = receipt.ArtifactSHA256
	report.Release = &receipt.Manifest
	return report
}

func HandleGetReleaseSecurity(w http.ResponseWriter, r *http.Request) {
	directory := os.Getenv("AEGIS_RELEASE_DIR")
	if directory == "" {
		directory = "/opt/aegisnas/current"
	}
	executable, _ := os.Executable()
	writeJSON(w, http.StatusOK, buildReleaseSecurityReport(directory, executable, time.Now().UTC()))
}
