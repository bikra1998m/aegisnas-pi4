package health

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

type Status struct {
	Status string `json:"status"`
}

func RegisterRoutes(r chi.Router) {
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Status{Status: "ok"})
	})
}

func StartServer(port int, logger *zap.Logger) {
	r := chi.NewRouter()
	RegisterRoutes(r)
	addr := fmt.Sprintf(":%d", port)
	logger.Info("health server listening", zap.String("addr", addr))
	if err := http.ListenAndServe(addr, r); err != nil {
		logger.Fatal("health server failed", zap.Error(err))
	}
}