package security

import (
	"net/http"
	"time"
)

// SetAccessTokenCookie drops or updates ONLY the short-lived access token cookie
// 💡 Used during Login, Register, and silent background Token Refreshes
func SetAccessTokenCookie(w http.ResponseWriter, accessToken string, duration time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    accessToken,
		Path:     "/",                       // Accessible across all application route trees
		Expires:  time.Now().Add(duration),  // Explicit expiration time
		MaxAge:   int(duration.Seconds()),   // Fallback configuration for older clients
		HttpOnly: true,                      // 🚨 Blocks client-side JS read execution (Neutralizes XSS)
		Secure:   false,                     // Set to 'true' in production environments over HTTPS
		SameSite: http.SameSiteLaxMode,      // 🔒 Protects against unauthorized cross-site requests
	})
}

// SetRefreshTokenCookie drops or updates ONLY the long-lived refresh token cookie
// 💡 Used strictly during initial Login or Registration steps
func SetRefreshTokenCookie(w http.ResponseWriter, refreshToken string, duration time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		Expires:  time.Now().Add(duration),
		MaxAge:   int(duration.Seconds()),
		HttpOnly: true,                      // 🚨 Anti-XSS protection
		Secure:   false,                     // Set to 'true' in production environments over HTTPS
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearAccessTokenCookie instantly kills the access session by forcing an expired timestamp
func ClearAccessTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0), // Wipes the cookie by sending it back to Jan 1, 1970
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearRefreshTokenCookie instantly kills the long-term refresh session
func ClearRefreshTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}