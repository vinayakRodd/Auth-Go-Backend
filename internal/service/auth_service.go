package service

import (
	"auth-go/internal/models"
	"auth-go/internal/repository"
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func (s *authService) RegisterUser(ctx context.Context, email, password string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	cleanedEmail := sanitizeInput(email)
	cleanedPassword := sanitizeInput(password)

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

    hashErr := ValidatePassword(cleanedPassword)
    if hashErr != nil {
        return nil, ErrInvalidLogin
    }

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

	return user, nil
}

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