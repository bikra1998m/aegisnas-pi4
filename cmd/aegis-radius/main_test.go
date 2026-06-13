package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestAddRadiusClientStoresNormalizedNASType(t *testing.T) {
	setupRadiusCommandDB(t)

	nasType, err := addRadiusClient("ap-lobby", "10.20.0.2", "secret", "unifi")
	require.NoError(t, err)
	assert.Equal(t, "ubnt", nasType)

	var stored string
	err = db.DB.QueryRow("SELECT nas_type FROM radius_clients WHERE shortname = ?", "ap-lobby").Scan(&stored)
	require.NoError(t, err)
	assert.Equal(t, "ubnt", stored)
}

func TestListRadiusClientsIncludesNASType(t *testing.T) {
	setupRadiusCommandDB(t)

	_, err := addRadiusClient("routeros-ap", "10.20.0.3", "secret", "routeros")
	require.NoError(t, err)

	var out bytes.Buffer
	require.NoError(t, listRadiusClients(&out))

	assert.Contains(t, out.String(), "NASType")
	assert.Contains(t, out.String(), "routeros-ap")
	assert.Contains(t, out.String(), "mikrotik")
}

func setupRadiusCommandDB(t *testing.T) {
	t.Helper()

	previousDB := db.DB
	tmpfile, err := os.CreateTemp("", "aegis-radius-command-*.db")
	require.NoError(t, err)
	require.NoError(t, tmpfile.Close())

	require.NoError(t, db.Init(tmpfile.Name()))
	require.NoError(t, db.Migrate())

	t.Cleanup(func() {
		_ = db.Close()
		db.DB = previousDB
		_ = os.Remove(tmpfile.Name())
	})
}
