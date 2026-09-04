package api

import (
	"auth-go/internal/models"
	"auth-go/internal/security"
	"net/http"
    "context"
)

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout_duration)
	defer cancel()

	if !hasValidMethod(w, r, http.MethodPost) {
		return
	}

	if h.CheckActiveSession(ctx, w, r) {
		return 
	}
	
	var req models.LoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	// 1. DB Verification Gate
	user, err := h.service.LoginUser(ctx, req.Email, req.Password)
	if err != nil {
		handleError(w, err) 
		return
	}

	// 2. 🚀 REUSABLE SESSION GENERATION CALL
	if err := h.issueSession(ctx, w, user.Email); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	h.respondWithEnvelope(w, http.StatusOK, "Logged in successfully", user.Email)
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout_duration)
	defer cancel()

	if !hasValidMethod(w, r, http.MethodPost) {
		return
	}

	if h.CheckActiveSession(ctx, w, r) {
		return 
	}
	
	var req models.RegisterRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	
	// 1. DB Registration Gate
	err := h.service.RegisterUser(ctx, req.Email, req.Password)
	if err != nil {
		handleError(w, err)
		return
	}

	// 2. 🚀 REUSABLE SESSION GENERATION CALL
	if err := h.issueSession(ctx, w, req.Email); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	h.respondWithEnvelope(w, http.StatusCreated, "User registered and logged in successfully", req.Email)
}


func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout_duration)
	defer cancel()

	if !hasValidMethod(w, r, http.MethodPost) {
		return
	}
	
	var req models.ResetPasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	// 🚀 UTILITY RUN: Instantly grab email and check cache health
	cachedEmail, err := h.verifyActiveSession(ctx, r)
	if err != nil || cachedEmail != req.Email {
		respondWithJSON(w, http.StatusUnauthorized, map[string]string{"error": "Session expired or invalid, please log in again"})
		return
	}

	// Database Action
	if err := h.service.ResetPassword(ctx, req.Email, req.NewPassword); err != nil {
		handleError(w, err)
		return
	}

	// 🚀 UTILITY RUN: Nuke the current session globally
	h.destroySessionFootprints(ctx, w, r)

	h.respondWithEnvelope(w, http.StatusOK, "Password reset successfully. Session invalidated, please log in again.", "")
}

func (h *AuthHandler) LogOut(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout_duration)
	defer cancel()

	if !hasValidMethod(w, r, http.MethodPost) {
		return
	}

	// 🚀 UTILITY RUN: Clear Redis keys and browser headers in one shot
	h.destroySessionFootprints(ctx, w, r)

	h.respondWithEnvelope(w, http.StatusOK, "Logged out successfully, session destroyed", "")
}

func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), timeout_duration)
	defer cancel()

	if !hasValidMethod(w, r, http.MethodPost) {
		return
	}

	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		respondWithJSON(w, http.StatusUnauthorized, map[string]string{"error": "Missing refresh token"})
		return
	}
	refreshTokenStr := cookie.Value


	email, err := h.cache.Get(ctx, "refresh:"+refreshTokenStr)
	if err != nil {
		respondWithJSON(w, http.StatusUnauthorized, map[string]string{"error": "Session expired, please log in again"})
		return
	}

	authSecret := h.secCfg.GetAuthSecret()
	authDuration := h.secCfg.GetAuthDuration()

	newAccessTokenStr, err := security.GenerateToken(email, authSecret, authDuration)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
 
	err = h.cache.Set(ctx, "access:"+newAccessTokenStr, email, authDuration)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	security.SetAccessTokenCookie(w, newAccessTokenStr, authDuration)

	h.respondWithEnvelope(w, http.StatusOK, "Access token refreshed successfully", email)
}