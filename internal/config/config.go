// // package config

// // import (
// // 	"os"
// // )

// // type Config struct {
// // 	Port  string
// // 	DBUrl string
// // }

// // func LoadConfig() Config {
// // 	// We read the "PORT" environment variable.
// // 	// If it's not set (empty), we default to "8080".
// // 	port := os.Getenv("PORT")

// // 	if port == "" {
// // 		port = "8080"
// // 	}

// // 	dbUrl := os.Getenv("DB_URL")
// // 	if dbUrl == "" {
// // 		panic("DB_URL environment variable is not set")
// // 	}

// // 	return Config{
// // 		Port:  port,
// // 		DBUrl: dbUrl,
// // 	}
// // }


// package config

// import (
// 	"os"
// 	"strconv"
// 	"time"
// )

// type Config struct {
// 	Port        string
// 	DBUrl       string
// 	JWTSecret   string        // ◄── Add this field
// 	JWTDuration time.Duration // ◄── Add this field
// }

// // 💡 Implements SecurityConfig.GetJWTSecret
// func (c Config) GetJWTSecret() string {
// 	return c.JWTSecret
// }

// // 💡 Implements SecurityConfig.GetJWTDuration
// func (c Config) GetJWTDuration() time.Duration {
// 	return c.JWTDuration
// }

// func LoadConfig() Config {
// 	// 1. Read existing config
// 	port := os.Getenv("PORT")
// 	if port == "" {
// 		port = "8080"
// 	}

// 	dbUrl := os.Getenv("DB_URL")
// 	if dbUrl == "" {
// 		panic("DB_URL environment variable is not set")
// 	}

// 	// 2. Read new JWT configuration strings from your .env
// 	jwtSecret := os.Getenv("JWT_SECRET")
// 	if jwtSecret == "" {
// 		// Secure default fallback or panic depending on your production preference
// 		jwtSecret = "change-me-immediately-in-production"
// 	}

// 	durationMinutesStr := os.Getenv("JWT_DURATION_MINUTES")
// 	if durationMinutesStr == "" {
// 		durationMinutesStr = "15" // Default fallback string if missing
// 	}

// 	// 3. Convert the string numbers to an integer format cleanly
// 	minutes, err := strconv.Atoi(durationMinutesStr)
// 	if err != nil {
// 		minutes = 15 // Secondary fallback if someone types "abc" in the .env by accident
// 	}

// 	return Config{
// 		Port:        port,
// 		DBUrl:       dbUrl,
// 		JWTSecret:   jwtSecret,
// 		JWTDuration: time.Duration(minutes) * time.Minute, // ◄── Converts your int to minutes!
// 	}
// }

package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port           string
	DBUrl          string
	// 🚀 Split JWT parameters for security boundaries
	AuthSecret     string        
	AuthDuration   time.Duration 
	RefreshSecret  string        
	RefreshDuration time.Duration 
}

// 💡 Implements SecurityConfig for short-lived access tokens
func (c Config) GetAuthSecret() string {
	return c.AuthSecret
}

func (c Config) GetAuthDuration() time.Duration {
	return c.AuthDuration
}

// 💡 Implements SecurityConfig for long-lived refresh tokens
func (c Config) GetRefreshSecret() string {
	return c.RefreshSecret
}

func (c Config) GetRefreshDuration() time.Duration {
	return c.RefreshDuration
}

func LoadConfig() Config {
	// 1. Basic Server Setup
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dbUrl := os.Getenv("DB_URL")
	if dbUrl == "" {
		panic("DB_URL environment variable is not set")
	}

	// 2. Read Access Token Configs (Short-lived)
	authSecret := os.Getenv("JWT_SECRET_AUTH")
	if authSecret == "" {
		authSecret = "super-secret-short-lived-access-key"
	}

	authMinStr := os.Getenv("JWT_AUTH_DURATION_MINUTES")
	if authMinStr == "" {
		authMinStr = "15" // Access tokens typically live for 15 minutes
	}
	authMin, err := strconv.Atoi(authMinStr)
	if err != nil {
		authMin = 15
	}

	// 3. Read Refresh Token Configs (Long-lived)
	refreshSecret := os.Getenv("JWT_SECRET_REFRESH")
	if refreshSecret == "" {
		refreshSecret = "completely-different-long-lived-refresh-key"
	}

	refreshDaysStr := os.Getenv("JWT_REFRESH_DURATION_DAYS")
	if refreshDaysStr == "" {
		refreshDaysStr = "7" // Refresh tokens typically live for 7 days
	}
	refreshDays, err := strconv.Atoi(refreshDaysStr)
	if err != nil {
		refreshDays = 7
	}

	return Config{
		Port:            port,
		DBUrl:           dbUrl,
		AuthSecret:      authSecret,
		AuthDuration:    time.Duration(authMin) * time.Minute,
		RefreshSecret:   refreshSecret,
		RefreshDuration: time.Duration(refreshDays) * 24 * time.Hour, // ◄── Multiplies to get full days!
	}
}