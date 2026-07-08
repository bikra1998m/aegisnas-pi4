package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

func TestHandleListRadiusClientsRedactsSecretsAndReturnsRadSecIdentity(t *testing.T) {
	file, err := os.CreateTemp("", "radius-client-api-*.db")
	require.NoError(t, err)
	path := file.Name()
	require.NoError(t, file.Close())
	require.NoError(t, db.Init(path))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() { _ = db.Close(); _ = os.Remove(path) })
	_, err = db.DB.Exec(`INSERT INTO radius_clients
		(shortname, ipaddr, secret, nas_type, transport, radsec_certificate_cn, enabled)
		VALUES ('secure-nas', '192.0.2.10', 'radsec', 'cisco', 'radsec', 'secure-nas.example.net', 1)`)
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	HandleListRadiusClients(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/radius-clients", nil))
	require.Equal(t, http.StatusOK, recorder.Code)
	assert.NotContains(t, recorder.Body.String(), `"secret":`)
	assert.NotContains(t, recorder.Body.String(), `"secret":"radsec"`)
	var clients []map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &clients))
	require.Len(t, clients, 1)
	assert.Equal(t, true, clients[0]["secret_set"])
	assert.Equal(t, "radsec", clients[0]["transport"])
	assert.Equal(t, "secure-nas.example.net", clients[0]["radsec_certificate_cn"])
}

func TestApplyRadiusClientUpdatePreservesBlankSecret(t *testing.T) {
	file, err := os.CreateTemp("", "radius-client-update-*.db")
	require.NoError(t, err)
	path := file.Name()
	require.NoError(t, file.Close())
	require.NoError(t, db.Init(path))
	require.NoError(t, db.Migrate())
	t.Cleanup(func() { _ = db.Close(); _ = os.Remove(path) })
	result, err := db.DB.Exec(`INSERT INTO radius_clients (shortname, ipaddr, secret, nas_type, enabled) VALUES ('ap', '192.0.2.20', 'keep-me', 'other', 1)`)
	require.NoError(t, err)
	id, err := result.LastInsertId()
	require.NoError(t, err)
	tx, err := db.DB.Begin()
	require.NoError(t, err)
	err = applyChange(tx, stagedChange{ResourceType: "radius_client", ResourceID: fmt.Sprint(id), Operation: "update", Data: `{"shortname":"ap","ip":"192.0.2.21","nas_type":"other","transport":"udp","enabled":true}`})
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	var secret string
	require.NoError(t, db.DB.QueryRow(`SELECT secret FROM radius_clients WHERE id = ?`, id).Scan(&secret))
	assert.Equal(t, "keep-me", secret)
}
