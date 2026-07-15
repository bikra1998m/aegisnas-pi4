package adminapi

import (
	"net/http"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/radius"
)

func HandleGetRadSecCredentials(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, radius.BuildRadSecCredentialReport(config.Get()))
}
