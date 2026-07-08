package vendoridentity

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	productconfigs "github.com/yourorg/aegisnas-pi4/configs"
)

const (
	EvidenceSchemaVersion = 1
	DocumentationPEN      = 32473
	defaultRegistryLimit  = 8 << 20
	defaultFetchTimeout   = 20 * time.Second
)

var registryUpdatedPattern = regexp.MustCompile(`(?i)^\(last updated\s+([0-9]{4}-[0-9]{2}-[0-9]{2})\)$`)

type AssignmentEvidence struct {
	SchemaVersion       int       `json:"schema_version"`
	PEN                 uint32    `json:"pen"`
	Organization        string    `json:"organization"`
	RegistryURL         string    `json:"registry_url"`
	RegistryLastUpdated string    `json:"registry_last_updated"`
	FetchedAt           time.Time `json:"fetched_at"`
	RegistrySHA256      string    `json:"registry_sha256"`
	RecordSHA256        string    `json:"record_sha256"`
}

type Fetcher struct {
	Client   *http.Client
	URL      string
	MaxBytes int64
	Now      func() time.Time
}

func NewFetcher() *Fetcher {
	return &Fetcher{
		Client:   &http.Client{Timeout: defaultFetchTimeout},
		URL:      productconfigs.IANAPrivateEnterpriseNumbersURL + "enterprise-numbers.txt",
		MaxBytes: defaultRegistryLimit,
		Now:      time.Now,
	}
}

func ValidateProductionPEN(pen int) error {
	switch {
	case pen < 1 || uint64(pen) > uint64(^uint32(0)-1):
		return fmt.Errorf("PEN %d is outside the assignable uint32 range", pen)
	case pen == productconfigs.AegisNASPlaceholderVendorID:
		return fmt.Errorf("PEN %d is the AegisNAS lab placeholder", pen)
	case pen == DocumentationPEN:
		return fmt.Errorf("PEN %d is reserved for documentation by RFC 5612", pen)
	default:
		return nil
	}
}

func (f *Fetcher) Fetch(ctx context.Context, pen int, expectedOrganization string) (AssignmentEvidence, error) {
	if err := ValidateProductionPEN(pen); err != nil {
		return AssignmentEvidence{}, err
	}
	expectedOrganization = normalizeOrganization(expectedOrganization)
	if expectedOrganization == "" {
		return AssignmentEvidence{}, errors.New("expected IANA organization is required")
	}

	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: defaultFetchTimeout}
	}
	registryURL := strings.TrimSpace(f.URL)
	if registryURL == "" {
		registryURL = productconfigs.IANAPrivateEnterpriseNumbersURL + "enterprise-numbers.txt"
	}
	limit := f.MaxBytes
	if limit <= 0 {
		limit = defaultRegistryLimit
	}
	now := f.Now
	if now == nil {
		now = time.Now
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, registryURL, nil)
	if err != nil {
		return AssignmentEvidence{}, fmt.Errorf("build IANA registry request: %w", err)
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", "AegisNAS vendor identity verifier")
	resp, err := client.Do(req)
	if err != nil {
		return AssignmentEvidence{}, fmt.Errorf("fetch IANA registry: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return AssignmentEvidence{}, fmt.Errorf("fetch IANA registry: unexpected HTTP status %d", resp.StatusCode)
	}

	payload, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return AssignmentEvidence{}, fmt.Errorf("read IANA registry: %w", err)
	}
	if int64(len(payload)) > limit {
		return AssignmentEvidence{}, fmt.Errorf("IANA registry exceeds the %d-byte safety limit", limit)
	}
	record, updated, err := findAssignment(payload, uint32(pen))
	if err != nil {
		return AssignmentEvidence{}, err
	}
	if !strings.EqualFold(normalizeOrganization(record.Organization), expectedOrganization) {
		return AssignmentEvidence{}, fmt.Errorf("PEN %d is assigned to %q, not %q", pen, record.Organization, expectedOrganization)
	}

	registryDigest := sha256.Sum256(payload)
	recordDigest := sha256.Sum256([]byte(fmt.Sprintf("%d\n%s\n", record.PEN, record.Organization)))
	return AssignmentEvidence{
		SchemaVersion:       EvidenceSchemaVersion,
		PEN:                 record.PEN,
		Organization:        record.Organization,
		RegistryURL:         registryURL,
		RegistryLastUpdated: updated,
		FetchedAt:           now().UTC(),
		RegistrySHA256:      hex.EncodeToString(registryDigest[:]),
		RecordSHA256:        hex.EncodeToString(recordDigest[:]),
	}, nil
}

func (e AssignmentEvidence) Validate(expectedPEN int, expectedOrganization string) error {
	if e.SchemaVersion != EvidenceSchemaVersion {
		return fmt.Errorf("unsupported assignment evidence schema %d", e.SchemaVersion)
	}
	if err := ValidateProductionPEN(int(e.PEN)); err != nil {
		return err
	}
	if expectedPEN > 0 && int(e.PEN) != expectedPEN {
		return fmt.Errorf("assignment evidence PEN %d does not match expected PEN %d", e.PEN, expectedPEN)
	}
	if normalizeOrganization(e.Organization) == "" {
		return errors.New("assignment evidence organization is required")
	}
	if expectedOrganization != "" && !strings.EqualFold(normalizeOrganization(e.Organization), normalizeOrganization(expectedOrganization)) {
		return fmt.Errorf("assignment evidence organization %q does not match %q", e.Organization, expectedOrganization)
	}
	if e.RegistryURL != productconfigs.IANAPrivateEnterpriseNumbersURL+"enterprise-numbers.txt" {
		return fmt.Errorf("assignment evidence registry URL %q is not the authoritative IANA text registry", e.RegistryURL)
	}
	if _, err := time.Parse("2006-01-02", e.RegistryLastUpdated); err != nil {
		return fmt.Errorf("assignment evidence registry update date is invalid: %w", err)
	}
	if e.FetchedAt.IsZero() {
		return errors.New("assignment evidence fetch time is required")
	}
	if !validSHA256(e.RegistrySHA256) || !validSHA256(e.RecordSHA256) {
		return errors.New("assignment evidence SHA-256 digests are invalid")
	}
	recordDigest := sha256.Sum256([]byte(fmt.Sprintf("%d\n%s\n", e.PEN, e.Organization)))
	if !strings.EqualFold(e.RecordSHA256, hex.EncodeToString(recordDigest[:])) {
		return errors.New("assignment evidence record digest does not match its PEN and organization")
	}
	return nil
}

func (e AssignmentEvidence) JSON() ([]byte, error) {
	if err := e.Validate(int(e.PEN), e.Organization); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

type assignmentRecord struct {
	PEN          uint32
	Organization string
}

func findAssignment(payload []byte, target uint32) (assignmentRecord, string, error) {
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	updated := ""
	var pending *uint32
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if updated == "" {
			if match := registryUpdatedPattern.FindStringSubmatch(strings.TrimSpace(line)); len(match) == 2 {
				updated = match[1]
			}
		}
		if pending != nil {
			if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
				organization := normalizeOrganization(line)
				if *pending == target {
					if organization == "" {
						return assignmentRecord{}, "", fmt.Errorf("PEN %d has an empty organization in the IANA registry", target)
					}
					if updated == "" {
						return assignmentRecord{}, "", errors.New("IANA registry does not contain a valid last-updated date")
					}
					return assignmentRecord{PEN: target, Organization: organization}, updated, nil
				}
				pending = nil
				continue
			}
			if strings.TrimSpace(line) != "" {
				pending = nil
			}
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed != line {
			continue
		}
		value, err := strconv.ParseUint(trimmed, 10, 32)
		if err == nil {
			pen := uint32(value)
			pending = &pen
		}
	}
	if err := scanner.Err(); err != nil {
		return assignmentRecord{}, "", fmt.Errorf("parse IANA registry: %w", err)
	}
	return assignmentRecord{}, "", fmt.Errorf("PEN %d is not present in the IANA registry", target)
}

func normalizeOrganization(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	return err == nil && len(decoded) == sha256.Size
}
