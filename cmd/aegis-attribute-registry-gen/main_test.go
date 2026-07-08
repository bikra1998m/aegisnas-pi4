package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadBoundedAndAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.csv")
	out := filepath.Join(dir, "nested", "registry.csv")
	require.NoError(t, os.WriteFile(source, []byte("registry\n"), 0o600))

	payload, err := readBounded(source)
	require.NoError(t, err)
	require.NoError(t, writeAtomic(out, payload))
	written, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, payload, written)
}

func TestReadBoundedRejectsOversizeInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.csv")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(maxRegistryBytes+1))
	require.NoError(t, f.Close())

	_, err = readBounded(path)
	require.ErrorContains(t, err, "exceeds")
}
