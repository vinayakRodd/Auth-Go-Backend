package security

import (
	"time"
	"github.com/golang-jwt/jwt/v5"
)

// Claims holds the structured data session payload that will be encrypted into the token
type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// GenerateToken creates a signed HS256 JWT string for a validated user
// 💡 FIXED: Removed userID from the input arguments list completely
func GenerateToken(email, secretKey string, duration time.Duration) (string, error) {
	expirationTime := time.Now().Add(duration)

	claims := &Claims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "auth-go-backend",
		},
	}

	// Create the token instance using the secure HS256 signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with your server's secret key bytes
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}