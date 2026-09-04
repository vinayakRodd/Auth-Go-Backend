package repository

import (
    "context"
    "auth-go/internal/models"
)

// AuthRepository defines the methods our service layer expects
type AuthRepository interface {
    CreateUser(ctx context.Context, user *models.User) error
    GetUserByEmail(ctx context.Context, email string) (*models.User, error)
    UpdatePasswordByEmail(ctx context.Context, email string, password string) error
    EmailExists(ctx context.Context, email string) (bool, error)
}