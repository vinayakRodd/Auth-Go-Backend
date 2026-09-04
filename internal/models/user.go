package models

import "time"

type User struct {
    ID        string    `json:"id"`
    Email     string    `json:"email"`
    Password  string    `json:"-"` // Use "-" to hide it when sending JSON responses
    CreatedAt time.Time `json:"created_at"`
}


// RegisterRequest handles data needed to create a new account
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest handles data needed for authentication
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// ResetPasswordRequest handles data needed to change a password
type ResetPasswordRequest struct {
	Email       string `json:"email"`
	NewPassword string `json:"password"` 
}


type UserResponse struct {
    Email string `json:"email"`
}

type EnvelopeResponse struct {
    Success bool          `json:"success"`
    Message string        `json:"message"`
    User    *UserResponse `json:"user,omitempty"` // Capitalize U here too
}