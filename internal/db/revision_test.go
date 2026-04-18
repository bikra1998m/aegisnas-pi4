package db

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveAndGetConfigRevision(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-*.db")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	err = Init(tmpfile.Name())
	require.NoError(t, err)
	defer Close()

	err = Migrate()
	require.NoError(t, err)

	configData := "test config content"
	id, err := SaveConfigRevision(configData, "test")
	assert.NoError(t, err)
	assert.Greater(t, id, 0)

	latest, err := GetLatestConfigRevision()
	assert.NoError(t, err)
	assert.Equal(t, configData, latest)

	byRev, err := GetConfigRevisionByNumber(1)
	assert.NoError(t, err)
	assert.Equal(t, configData, byRev)
}