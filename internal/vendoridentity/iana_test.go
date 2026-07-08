package vendoridentity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const registryFixture = `
PRIVATE ENTERPRISE NUMBERS

(last updated 2026-07-06)

32472
  Before Example, Inc.
    Example Contact
      contact&example.test
32473
  Example Enterprise Number for Documentation Use
    IETF
      ietf&ietf.org
424242
  AegisNAS Systems Ltd.
    Registry Contact
      registry&example.test
424243
  After Example, Inc.
    Example Contact
      contact&example.test
`

func TestFetcherVerifiesExactIANAAssignment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "text/plain", r.Header.Get("Accept"))
		_, _ = w.Write([]byte(registryFixture))
	}))
	defer server.Close()

	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	fetcher := &Fetcher{Client: server.Client(), URL: server.URL, MaxBytes: 1 << 20, Now: func() time.Time { return now }}
	evidence, err := fetcher.Fetch(context.Background(), 424242, " AegisNAS   Systems Ltd. ")
	require.NoError(t, err)
	assert.EqualValues(t, 424242, evidence.PEN)
	assert.Equal(t, "AegisNAS Systems Ltd.", evidence.Organization)
	assert.Equal(t, "2026-07-06", evidence.RegistryLastUpdated)
	assert.Equal(t, now, evidence.FetchedAt)
	assert.Len(t, evidence.RegistrySHA256, 64)
	assert.Len(t, evidence.RecordSHA256, 64)

	evidence.RegistryURL = "https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers.txt"
	require.NoError(t, evidence.Validate(424242, "AegisNAS Systems Ltd."))
}

func TestFetcherRejectsWrongOrganizationAndMissingPEN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(registryFixture))
	}))
	defer server.Close()
	fetcher := &Fetcher{Client: server.Client(), URL: server.URL}

	_, err := fetcher.Fetch(context.Background(), 424242, "Imposter Corp")
	assert.ErrorContains(t, err, `assigned to "AegisNAS Systems Ltd."`)
	_, err = fetcher.Fetch(context.Background(), 424244, "Missing Corp")
	assert.ErrorContains(t, err, "is not present")
}

func TestFetcherBoundsRegistryResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 129)))
	}))
	defer server.Close()
	fetcher := &Fetcher{Client: server.Client(), URL: server.URL, MaxBytes: 128}

	_, err := fetcher.Fetch(context.Background(), 424242, "AegisNAS Systems Ltd.")
	assert.ErrorContains(t, err, "safety limit")
}

func TestValidateProductionPENRejectsReservedAndLabValues(t *testing.T) {
	for _, pen := range []int{0, 55555, DocumentationPEN} {
		assert.Error(t, ValidateProductionPEN(pen), "PEN %d", pen)
	}
	assert.NoError(t, ValidateProductionPEN(424242))
}

func TestAssignmentEvidenceDetectsTampering(t *testing.T) {
	record, updated, err := findAssignment([]byte(registryFixture), 424242)
	require.NoError(t, err)
	assert.Equal(t, "2026-07-06", updated)
	assert.Equal(t, "AegisNAS Systems Ltd.", record.Organization)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(registryFixture))
	}))
	defer server.Close()
	fetcher := &Fetcher{Client: server.Client(), URL: server.URL}
	evidence, err := fetcher.Fetch(context.Background(), 424242, record.Organization)
	require.NoError(t, err)
	evidence.RegistryURL = "https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers.txt"
	evidence.Organization = "Changed Organization"
	assert.ErrorContains(t, evidence.Validate(424242, "Changed Organization"), "record digest")
}
