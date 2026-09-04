package api

import (
    "net/http"
    "time"    
)

// SetupRoutes centralizes all your endpoint definitions
func SetupRoutes(authHandler *AuthHandler, healthHandler *HealthHandler, middlewareHandler *MiddlewareManager) http.Handler {
    mux := http.NewServeMux()

    authLimit := middlewareHandler.RateLimit(ratelimitVal, time.Minute)
    
    // Auth Routes
    mux.Handle("POST /register", authLimit(http.HandlerFunc(authHandler.Register)))
	mux.Handle("POST /login", authLimit(http.HandlerFunc(authHandler.Login)))
	mux.Handle("POST /reset-password", authLimit(http.HandlerFunc(authHandler.ResetPassword)))
	mux.Handle("POST /logout", authLimit(http.HandlerFunc(authHandler.LogOut)))
    mux.Handle("POST /refresh", authLimit(http.HandlerFunc(authHandler.RefreshToken)))
    

    // System Routes
    mux.HandleFunc("GET /health", healthHandler.Check)

    // 💡 Return the multiplexer wrapped inside your CORS protective layer!
	return enableCORS(mux)
}
