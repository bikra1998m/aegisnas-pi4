package main

import (
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"github.com/yourorg/aegisnas-pi4/internal/config"
)

func TestRegisterAdminRoutesDoesNotPanic(t *testing.T) {
	router := chi.NewRouter()
	cfg := &config.Config{}

	require.NotPanics(t, func() {
		registerAdminRoutes(router, cfg)
	})
}
