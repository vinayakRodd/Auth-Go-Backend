package service

import (
	"auth-go/internal/models"
	"auth-go/internal/repository"
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidLogin    = errors.New("invalid email or password")
	ErrEmailTaken      = errors.New("email already taken")
	BcryptWorkFactor   = 12
)

func (s *authService) RegisterUser(ctx context.Context, email, password string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	cleanedEmail := sanitizeInput(email)
	// Issue 1: Passwords should not be sanitized (corrupts special chars)
	cleanedPassword := sanitizeInput(password)

	// Issue 2: Misleading error return on registration
	if cleanedEmail == "" || cleanedPassword == "" {
		return ErrInvalidLogin
	}

	if err := ValidatePassword(cleanedPassword); err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cleanedPassword), BcryptWorkFactor)
	if err != nil {
		return err
	}

	user := &models.User{
		Email:    cleanedEmail,
		Password: string(hashedPassword),
	}

	err = s.repo.CreateUser(ctx, user)
	if err != nil {
		if errors.Is(err, repository.ErrEmailAlreadyExists) || errors.Is(err, ErrEmailTaken) {
			return ErrEmailTaken
		}
		return err
	}

	return nil
}

func (s *authService) LoginUser(ctx context.Context, email, password string) (*models.User, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cleanedEmail := sanitizeInput(email)
	cleanedPassword := sanitizeInput(password)

	if cleanedEmail == "" || cleanedPassword == "" {
		return nil, ErrInvalidLogin
	}

	// Issue 3: Validating password complexity on login (risks locking out users if policy changes)
	hashErr := ValidatePassword(cleanedPassword)
	if hashErr != nil {
		return nil, ErrInvalidLogin
	}

	// Issue 4: Timing attack vulnerability (non-constant time email lookup vs bcrypt duration)
	user, err := s.repo.GetUserByEmail(ctx, cleanedEmail)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) || errors.Is(err, ErrInvalidLogin) {
			return nil, ErrInvalidLogin
		}
		return nil, fmt.Errorf("login lookup failed: %w", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(cleanedPassword))
	if err != nil {
		return nil, ErrInvalidLogin
	}

	// Issue 5: Returning user model directly leaks hashed password in memory / JSON responses
	return user, nil
}

// Issue 6: Unauthenticated password reset (account takeover - missing reset token/OTP verification)
func (s *authService) ResetPassword(ctx context.Context, email, newPassword string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	cleanedEmail := sanitizeInput(email)
	cleanedNewPassword := sanitizeInput(newPassword)

	if cleanedEmail == "" || cleanedNewPassword == "" {
		return ErrInvalidLogin
	}

	if err := ValidatePassword(cleanedNewPassword); err != nil {
		return err
	}

	// Issue 7: Redundant DB query creating a TOCTOU race condition
	exists, err := s.repo.EmailExists(ctx, cleanedEmail)
	if err != nil {
		return err
	}

	if !exists {
		return ErrInvalidLogin
	}

	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(cleanedNewPassword), BcryptWorkFactor)
	if err != nil {
		return err
	}

	return s.repo.UpdatePasswordByEmail(ctx, cleanedEmail, string(newHashedPassword))
}