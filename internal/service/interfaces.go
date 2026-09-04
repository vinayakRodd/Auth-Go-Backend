
package service

import (
	"context"
	"auth-go/internal/models"
)

// 💡 1. Local Repository Contract (Owned by the service layer)
type AuthRepository interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	UpdatePasswordByEmail(ctx context.Context, email string, password string) error
	EmailExists(ctx context.Context, email string) (bool, error)
}


// 💡 3. The Shared Struct (Uses our local AuthRepository interface)
type authService struct {
	repo AuthRepository 
}


// 💡 2. Outward Service Contract (Exposed to the handlers)
type AuthService interface {
	RegisterUser(ctx context.Context, email, password string) error
	LoginUser(ctx context.Context, email, password string) (*models.User, error)
	ResetPassword(ctx context.Context, email, newPassword string) error
}


// 💡 4. The Single Constructor
func NewAuthService(repo AuthRepository) AuthService {
	return &authService{repo: repo}
}