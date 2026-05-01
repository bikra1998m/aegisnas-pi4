package adminapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/db"
)

type contextKey string

const userContextKey contextKey = "user"
const tokenHashContextKey contextKey = "token_hash"
const tokenDescriptionContextKey contextKey = "token_description"

// AuthMiddleware validates the Bearer token.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}
		parts := strings.Split(auth, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "invalid authorization format", http.StatusUnauthorized)
			return
		}
		token := parts[1]
		tokenHash := hashToken(token)
		// Validate token against database
		var enabled bool
		var createdBy, description string
		err := db.DB.QueryRow(`SELECT enabled, COALESCE(created_by, ''), COALESCE(description, '')
			FROM api_tokens
			WHERE (token = ? OR token = ?)
				AND (expires_at IS NULL OR expires_at > datetime('now'))`,
			token, tokenHash).Scan(&enabled, &createdBy, &description)
		if err != nil || !enabled {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
		// Update last_used
		_, _ = db.DB.Exec(`UPDATE api_tokens SET last_used = datetime('now') WHERE token = ? OR token = ?`, token, tokenHash)
		user := createdBy
		if user == "" {
			user = description
		}
		if user == "" {
			user = "api-token"
		}
		ctx := context.WithValue(r.Context(), userContextKey, user)
		ctx = context.WithValue(ctx, tokenHashContextKey, tokenHash)
		ctx = context.WithValue(ctx, tokenDescriptionContextKey, description)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func tokenHashFromRequest(r *http.Request) string {
	if value, ok := r.Context().Value(tokenHashContextKey).(string); ok {
		return value
	}
	return ""
}

func tokenDescriptionFromRequest(r *http.Request) string {
	if value, ok := r.Context().Value(tokenDescriptionContextKey).(string); ok {
		return value
	}
	return ""
}
