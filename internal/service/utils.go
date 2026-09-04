
package service

import (
	"strings"
	"golang.org/x/text/unicode/norm"
)

// sanitizeInput cleans whitespaces and forces standard Unicode
func sanitizeInput(input string) string {
	// 1. Strip accidental leading/trailing spaces
	cleaned := strings.TrimSpace(input)
	
	// 3. Normalize Unicode bytes to NFC form (collapses duplicate character representations)
	return norm.NFC.String(cleaned)
}

func ValidatePassword(password string) error {
	// 1. Enforce length boundary {8,32}
	if len(password) < MinPasswordLength || len(password) > MaxPasswordLength {
		return DoesNotMeetLengthRequirements
	}

	// 2. Enforce at least one lowercase letter
	if !hasLowercase.MatchString(password) {
		return DoesNotHaveLowercase
	}

	// 3. Enforce at least one uppercase letter
	if !hasUppercase.MatchString(password) {
		return DoesNotHaveUppercase
	}

	// 4. Enforce at least one digit
	if !hasDigit.MatchString(password) {
		return DoesNotHaveDigit
	}

	// 5. Enforce at least one special character
	if !hasSpecial.MatchString(password) {
		return DoesNotHaveSpecial
	}

	return nil
}
