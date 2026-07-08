package vendoridentity

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLiveIANAAssignment(t *testing.T) {
	penText := os.Getenv("AEGIS_TEST_IANA_PEN")
	organization := os.Getenv("AEGIS_TEST_IANA_ORGANIZATION")
	if penText == "" || organization == "" {
		t.Skip("set AEGIS_TEST_IANA_PEN and AEGIS_TEST_IANA_ORGANIZATION for live IANA verification")
	}
	pen, err := strconv.Atoi(penText)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	evidence, err := NewFetcher().Fetch(ctx, pen, organization)
	require.NoError(t, err)
	require.NoError(t, evidence.Validate(pen, organization))
}

func BenchmarkFindAssignment(b *testing.B) {
	payload := []byte(registryFixture)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := findAssignment(payload, 424242); err != nil {
			b.Fatal(err)
		}
	}
}
