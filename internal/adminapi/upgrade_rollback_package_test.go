package adminapi

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/upgrade"
)

func TestHandleDownloadUpgradeRollbackPackage(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	original := createUpgradeRollbackPackageFn
	createUpgradeRollbackPackageFn = func(cfg *config.Config, configPath string) ([]byte, string, upgrade.RollbackPackageManifest, error) {
		buffer := &bytes.Buffer{}
		archive := zip.NewWriter(buffer)
		entry, err := archive.Create("manifest.json")
		require.NoError(t, err)
		_, err = entry.Write([]byte(`{"current_schema_version":8,"target_schema_version":8}`))
		require.NoError(t, err)
		require.NoError(t, archive.Close())
		return buffer.Bytes(), "aegisnas-upgrade-rollback-test.zip", upgrade.RollbackPackageManifest{
			CurrentSchemaVersion: 8,
			TargetSchemaVersion:  8,
		}, nil
	}
	t.Cleanup(func() {
		createUpgradeRollbackPackageFn = original
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/upgrade-rollback-package", nil)
	rec := httptest.NewRecorder()
	HandleDownloadUpgradeRollbackPackage(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/zip", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "aegisnas-upgrade-rollback-test.zip")
	assert.Equal(t, "8", rec.Header().Get("X-AegisNAS-Schema-Version"))
	assert.NotEmpty(t, rec.Body.Bytes())
}

func TestHandleInspectUpgradeRollbackPackage(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	original := inspectUpgradeRollbackPackageFn
	inspectUpgradeRollbackPackageFn = func(packageBytes []byte, cfg *config.Config, configPath string) (upgrade.RollbackPackageInspection, error) {
		return upgrade.RollbackPackageInspection{
			CompatibilityStatus:    "online_supported",
			OnlineRestoreSupported: true,
		}, nil
	}
	t.Cleanup(func() {
		inspectUpgradeRollbackPackageFn = original
	})

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("package", "rollback.zip")
	require.NoError(t, err)
	_, err = part.Write([]byte("package-bytes"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/upgrade-rollback-package/inspect", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	HandleInspectUpgradeRollbackPackage(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	assert.Equal(t, "rollback.zip", payload["filename"])
}

func TestHandleRestoreUpgradeRollbackPackage(t *testing.T) {
	_ = prepareSupportBundleTestConfig(t)

	original := restoreUpgradeRollbackPackageFn
	restoreUpgradeRollbackPackageFn = func(cfg *config.Config, configPath string, packageBytes []byte, confirmationText string) (upgrade.RollbackRestoreResult, error) {
		return upgrade.RollbackRestoreResult{
			RestartRequired:    true,
			SafetyPackagePath:  "/var/lib/aegisnas/upgrade-rollback/safety/rollback.zip",
			DatabaseBackupPath: "/var/lib/aegisnas/data.db.pre-rollback.bak",
			Inspection: upgrade.RollbackPackageInspection{
				CompatibilityStatus:    "online_supported",
				OnlineRestoreSupported: true,
			},
		}, nil
	}
	t.Cleanup(func() {
		restoreUpgradeRollbackPackageFn = original
	})

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("package", "rollback.zip")
	require.NoError(t, err)
	_, err = part.Write([]byte("package-bytes"))
	require.NoError(t, err)
	require.NoError(t, writer.WriteField("confirmation_text", "RESTORE UPGRADE ROLLBACK"))
	require.NoError(t, writer.Close())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/upgrade-rollback-package/restore", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	HandleRestoreUpgradeRollbackPackage(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"restart_required":true`)
	assert.Contains(t, rec.Body.String(), `"status":"restored"`)
}
