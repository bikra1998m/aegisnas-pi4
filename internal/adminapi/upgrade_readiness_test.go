package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	upgradepkg "github.com/yourorg/aegisnas-pi4/internal/upgrade"
)

func TestHandleGetUpgradeReadiness(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	original := assessUpgradeReadinessFn
	assessUpgradeReadinessFn = func(cfg *config.Config, configPath string) (upgradepkg.ReadinessReport, error) {
		return upgradepkg.ReadinessReport{
			ConfigPath:           configPath,
			DatabasePath:         cfg.Database.Path,
			CurrentSchemaVersion: 8,
			TargetSchemaVersion:  8,
			ConfigValid:          true,
			Rehearsal: upgradepkg.MigrationRehearsal{
				Ran:       true,
				Succeeded: true,
			},
		}, nil
	}
	t.Cleanup(func() {
		assessUpgradeReadinessFn = original
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/upgrade-readiness", nil)
	rec := httptest.NewRecorder()
	HandleGetUpgradeReadiness(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload upgradepkg.ReadinessReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.True(t, payload.ConfigValid)
	assert.True(t, payload.Rehearsal.Succeeded)
	assert.Equal(t, 8, payload.TargetSchemaVersion)
}
