package dnsmasq

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLeasesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq.leases")
	content := "1893456000 aa:bb:cc:dd:ee:ff 192.168.50.10 laptop 01:aa\n0 11:22:33:44:55:66 192.168.50.11 * *\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	leases, err := ParseLeasesFile(path, time.Unix(1893450000, 0), map[string]struct{}{
		"mac:aa:bb:cc:dd:ee:ff": {},
	})
	require.NoError(t, err)
	require.Len(t, leases, 2)

	assert.Equal(t, "192.168.50.10", leases[0].IP)
	assert.Equal(t, "laptop", leases[0].Hostname)
	assert.True(t, leases[0].Reservation)
	assert.False(t, leases[0].Expired)
	assert.Equal(t, "never", leases[1].ExpiresAt)
	assert.Empty(t, leases[1].Hostname)
}
