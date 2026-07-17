package adminapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/yourorg/aegisnas-pi4/internal/config"
	"github.com/yourorg/aegisnas-pi4/internal/db"
)

type contextKey string

const userContextKey contextKey = "user"
const tokenHashContextKey contextKey = "token_hash"
const tokenDescriptionContextKey contextKey = "token_description"

type adminBearerValidation struct {
	TokenHash   string
	CreatedBy   string
	Description string
	User        string
	Identity    AdminIdentity
}

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
		validation, err := validateAdminBearerToken(parts[1])
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
		if webAuthnStepUpRequiredForBearer(r, validation) {
			http.Error(w, "admin passkey step-up required", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey, validation.User)
		ctx = context.WithValue(ctx, tokenHashContextKey, validation.TokenHash)
		ctx = context.WithValue(ctx, tokenDescriptionContextKey, validation.Description)
		ctx = withAdminIdentity(ctx, validation.Identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validateAdminBearerToken(token string) (adminBearerValidation, error) {
	token = strings.TrimSpace(token)
	if token == "" || db.DB == nil {
		return adminBearerValidation{}, errors.New("missing token")
	}
	tokenHash := hashToken(token)
	var enabled bool
	var createdBy, description string
	err := db.DB.QueryRow(`SELECT enabled, COALESCE(created_by, ''), COALESCE(description, '')
		FROM api_tokens
		WHERE (token = ? OR token = ?)
			AND (expires_at IS NULL OR expires_at > datetime('now'))`,
		token, tokenHash).Scan(&enabled, &createdBy, &description)
	if err != nil || !enabled {
		return adminBearerValidation{}, errors.New("invalid or expired token")
	}
	_, _ = db.DB.Exec(`UPDATE api_tokens SET last_used = datetime('now') WHERE token = ? OR token = ?`, token, tokenHash)
	user := createdBy
	if user == "" {
		user = description
	}
	if user == "" {
		user = "api-token"
	}
	identity, err := resolveAdminIdentity(tokenHash, createdBy, description)
	if err != nil {
		return adminBearerValidation{}, err
	}
	return adminBearerValidation{
		TokenHash:   tokenHash,
		CreatedBy:   createdBy,
		Description: description,
		User:        user,
		Identity:    identity,
	}, nil
}

func webAuthnStepUpRequiredForBearer(r *http.Request, validation adminBearerValidation) bool {
	cfg := config.Get()
	if cfg == nil {
		return false
	}
	if strings.HasPrefix(validation.Description, adminWebAuthnSessionDescription) {
		return false
	}
	required, monitorAllowed := adminWebAuthnRequiredForIdentity(cfg, validation.Identity, validation.Description, "token")
	if !required {
		return false
	}
	if monitorAllowed {
		runtime, _ := adminWebAuthnRuntimeFromRequest(cfg, r)
		recordAdminWebAuthnMonitorAllowed(cfg, validation.Identity, "token", runtime, "bearer token would require passkey step-up")
		return false
	}
	return true
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
