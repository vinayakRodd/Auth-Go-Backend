package api

import (
	"context"
	"auth-go/internal/models"
	"time"

)


type AuthManager interface {
	RegisterUser(ctx context.Context, email, password string) error
	LoginUser(ctx context.Context, email, password string) (*models.User, error)
	ResetPassword(ctx context.Context, email, newPassword string) error
}

type SecurityConfig interface {
	GetAuthSecret() string
	GetAuthDuration() time.Duration
	GetRefreshSecret() string
	GetRefreshDuration() time.Duration
}

type CacheManager interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Get(ctx context.Context, key string) (string, error)
}

type AuthHandler struct {
	service AuthManager
	secCfg  SecurityConfig 
	cache CacheManager
}

// Update the constructor to take the cache instance
func NewAuthHandler(svc AuthManager, cfg SecurityConfig, cache CacheManager) *AuthHandler {
	return &AuthHandler{
		service: svc,
		secCfg:  cfg,
		cache:   cache, // ◄── 5. Bound to memory here!
	}
}