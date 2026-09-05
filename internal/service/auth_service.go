package service

import (
	"auth-go/internal/models"
	"context"
	"errors"
	"fmt"
    "log/slog"
	"golang.org/x/crypto/bcrypt"
)
 
func (s *authService) LoginUser(ctx context.Context, email, password string) (*models.User, error) {

    if err := ctx.Err(); err != nil {
        return nil, err // Returns context.Canceled or context.DeadlineExceeded
    }
    

    slog.Info("LoginUser called with email: ", "email", email)
    cleanedEmail := sanitizeInput(email)

    // 2. ONLY trim whitespace from the password. 
    // Do NOT lowercase it or pass it through email sanitization logic!
    cleanedPassword := sanitizeInput(password)

    // 3. Fail early if either field is missing
    if cleanedEmail == "" || cleanedPassword == "" {
        return nil, ErrInvalidLogin 
    }


    if err := ctx.Err(); err != nil {   
        
        return nil, err // Returns context.DeadlineExceeded
    }
   
    // 4. Look up the user in the database
    user, err := s.repo.GetUserByEmail(ctx, cleanedEmail)
    if err != nil {

        if err := ctx.Err(); err != nil {   
            
            return nil, err // Returns context.DeadlineExceeded
        }
        // Mask the error to prevent hackers from guessing which emails exist
        if errors.Is(err, ErrInvalidLogin) {
            return nil, ErrInvalidLogin 
        }
        return nil, fmt.Errorf("login lookup failed: %w", err)
    }

    // 5. Verify the password against the stored bcrypt hash
    err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(cleanedPassword))
    if err != nil {
        // Return the exact same generic error for a wrong password
        return nil, ErrInvalidLogin 
    }

    if err := ctx.Err(); err != nil {   
        return nil, err // Returns context.DeadlineExceeded
    }

    // 6. Success
    return user, nil
}

func (s *authService) ResetPassword(ctx context.Context, email, newPassword string) error {

    if err := ctx.Err(); err != nil {
        return err // Returns context.Canceled or context.DeadlineExceeded
    }
    
    cleanedEmail := sanitizeInput(email)
    cleanedNewPassword := sanitizeInput(newPassword)

    if cleanedEmail == "" || cleanedNewPassword == "" {
		return ErrInvalidLogin // Returns generic "invalid email or password"
	}

    pwd_err := ValidatePassword(cleanedNewPassword);
    if  pwd_err != nil {
        return pwd_err
    }

    if err := ctx.Err(); err != nil {   
        return err // Returns context.DeadlineExceeded
    }


    // 1. Check if the email exists in the database
    exists, err := s.repo.EmailExists(ctx, cleanedEmail)
    if err != nil {
        return err // Database error
    }
    
    if !exists {
        return ErrInvalidLogin
    }

    if err := ctx.Err(); err != nil {   
        
        return err // Returns context.DeadlineExceeded
    }

    newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(cleanedNewPassword), BcryptWorkFactor)
    if err != nil {

        return err
    }

    if err := ctx.Err(); err != nil {   
        return err // Returns context.DeadlineExceeded
    }

    // 3. Update the password in the database
    return s.repo.UpdatePasswordByEmail(ctx, cleanedEmail, string(newHashedPassword))
}