package api

import (
	"encoding/json"
	"net/http"
	"errors"
	"context"
	"auth-go/internal/service" 
	"auth-go/internal/security"
	"auth-go/internal/models"

)

// hasValidMethod ensures the incoming request matches the expected HTTP method.
func hasValidMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		respondWithJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})	
		return false
	}
	return true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	// Enforce 1MB payload limitation boundary
	r.Body = http.MaxBytesReader(w, r.Body, max_bytes)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		// Declare an empty pointer target of Go's native MaxBytesError type
		var maxBytesErr *http.MaxBytesError
		
		// Check if the error was caused by exceeding the MaxBytesReader ceiling
		if errors.As(err, &maxBytesErr) {
			respondWithJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "Payload limit exceeded: Request body cannot be larger than 1MB"})
			return false
		}

		// Fallback for standard malformed JSON or unexpected fields
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request payload context syntax"})
		return false
	}
	return true
}

// respondWithJSON standardizes payload delivery and hardens default headers.
func respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	// 3. PROTOCOL SECURITY HARDENING: Inject defensive payload descriptors.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff") // Prevents browser MIME sniffing
	w.Header().Set("X-Frame-Options", "DENY")           // Clickjacking defense

	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func handleError(w http.ResponseWriter, err error) {
	status, msg := MapErrorToHTTP(err)
	respondWithJSON(w, status, map[string]string{"error": msg})
}

func MapErrorToHTTP(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}

	// 1. Check explicit overrides first
	if errors.Is(err, service.ErrEmailTaken) {
		return http.StatusConflict, err.Error()
	}
	
	if errors.Is(err, service.ErrInvalidLogin) {
		return http.StatusUnauthorized, err.Error()
	}

	
	if errors.Is(err,service.ErrInternalServer){
		return http.StatusInternalServerError, err.Error()
	}

	
	return http.StatusBadRequest, err.Error()
}


// GetSecurityConfig extracts the configuration directly from the handler's service layer.
func (h *AuthHandler) GetSecurityConfig() (SecurityConfig, bool) {
	cfg, ok := h.service.(SecurityConfig)
	return cfg, ok
}


// CheckActiveSession intercepts public endpoints to see if a valid session already exists.
// Returns true if an active session was found and handled (short-circuited), false otherwise.
func (h *AuthHandler) CheckActiveSession(ctx context.Context, w http.ResponseWriter, r *http.Request) bool {
	activeCookie, err := r.Cookie("auth_token")
	if err != nil {
		return false // No cookie present, proceed with normal handler flow
	}

	// Look up the token string in the access namespace within Redis
	cachedEmail, cacheErr := h.cache.Get(ctx, "access:"+activeCookie.Value)
	
	// If the token exists in Redis without error, they are actively logged in!
	if cacheErr == nil && cachedEmail != "" {
		respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": "You are already logged in",
			"user": map[string]string{
				"email": cachedEmail,
			},
		})
		return true // Session found and handled!
	}

	return false // Cookie was invalid or expired in cache, proceed with normal handler flow
}

// issueSession encapsulates token generation, Redis seeding, and cookie dispatching.
// Returns an error if token generation or cache storage fails.
func (h *AuthHandler) issueSession(ctx context.Context, w http.ResponseWriter, email string) error {
	// 1. Fetch separate secrets and structural durations straight from the configuration layer
	authSecret := h.secCfg.GetAuthSecret()
	authDuration := h.secCfg.GetAuthDuration()
	refreshSecret := h.secCfg.GetRefreshSecret()
	refreshDuration := h.secCfg.GetRefreshDuration()

	// 2. Generate both cryptographic JWT strings using their dedicated configs
	accessTokenString, err := security.GenerateToken(email, authSecret, authDuration)
	if err != nil {
		return err
	}

	refreshTokenString, err := security.GenerateToken(email, refreshSecret, refreshDuration)
	if err != nil {
		return err
	}

	// 3. REDIS STORAGE: Store both keys using clean domain namespaces
	err = h.cache.Set(ctx, "access:"+accessTokenString, email, authDuration)
	if err != nil {
		return err
	}

	err = h.cache.Set(ctx, "refresh:"+refreshTokenString, email, refreshDuration)
	if err != nil {
		return err
	}

	// 4. Attach both secure HttpOnly cookies to the response header
	security.SetAccessTokenCookie(w, accessTokenString, authDuration)
	security.SetRefreshTokenCookie(w, refreshTokenString, refreshDuration)

	return nil
}

// verifyActiveSession extracts the access token and checks if it's alive in Redis.
// Returns the associated email or an error if missing/expired.
func (h *AuthHandler) verifyActiveSession(ctx context.Context, r *http.Request) (string, error) {
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		return "", errors.New("missing session token")
	}

	cachedEmail, cacheErr := h.cache.Get(ctx, "access:"+cookie.Value)
	if cacheErr != nil || cachedEmail == "" {
		return "", errors.New("session expired or invalid")
	}

	return cachedEmail, nil
}

// destroySessionFootprints instantly deletes the session tokens out of Redis and clear browser cookies.
func (h *AuthHandler) destroySessionFootprints(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if accessCookie, err := r.Cookie("auth_token"); err == nil {
		_ = h.cache.Set(ctx, "access:"+accessCookie.Value, "", -1)
	}
	if refreshCookie, err := r.Cookie("refresh_token"); err == nil {
		_ = h.cache.Set(ctx, "refresh:"+refreshCookie.Value, "", -1)
	}
	
	security.ClearAccessTokenCookie(w)
	security.ClearRefreshTokenCookie(w)
}

func (h *AuthHandler) respondWithEnvelope(w http.ResponseWriter, statusCode int, message string, email string) {
	var userPayload *models.UserResponse // ◄── Explicitly use the imported package models
	
	if email != "" {
		userPayload = &models.UserResponse{Email: email}
	}

	response := models.EnvelopeResponse{
		Success: true,
		Message: message,
		User:    userPayload,
	}

	respondWithJSON(w, statusCode, response)
}