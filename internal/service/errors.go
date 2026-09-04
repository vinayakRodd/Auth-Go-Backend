package service

import (
	"errors"
	"regexp"
)

const (
	MinPasswordLength = 8  // Enforces structural account security policies
	MaxPasswordLength = 32 // Enforces structural account security policies
	BcryptWorkFactor  = 12 // Adjust this based on your server's performance capabilities
)

var (

    ErrEmailTaken   = errors.New("email already registered")
    ErrInvalidLogin = errors.New("invalid email or password")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInternalServer  = errors.New("Internal server error. Please try again later.")
	ErrNotFound = errors.New("record not found")

	hasLowercase = regexp.MustCompile(`[a-z]`)
	hasUppercase = regexp.MustCompile(`[A-Z]`)
	hasDigit     = regexp.MustCompile(`[0-9]`)
	hasSpecial   = regexp.MustCompile(`[@$!%*?&^]`)

	DoesNotHaveLowercase = errors.New("password must contain at least one lowercase letter")
	DoesNotHaveUppercase = errors.New("password must contain at least one uppercase letter")
	DoesNotHaveDigit     = errors.New("password must contain at least one numeric digit")
	DoesNotHaveSpecial   = errors.New("password must contain at least one special character @$!%*?&^")
	DoesNotMeetLengthRequirements = errors.New("password must be between 8 and 32 characters long")
	
)