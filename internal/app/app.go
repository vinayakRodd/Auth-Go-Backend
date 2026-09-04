package app

import (
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"time"
	"context"

	"auth-go/internal/api"
	"auth-go/internal/config"
	"auth-go/internal/repository"
	"auth-go/internal/service"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9" // Import the official redis driver
)

func InitLogger() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
}

func LoadConfig() config.Config {
	err := godotenv.Load()
	if err != nil {
		slog.Warn("No .env file found, relying on system environment variables")
	}
	return config.LoadConfig()
}

func SetupDatabaseConnection(dbURL string) *sql.DB {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}

	// ─── CONNECTION POOL SECURITY HARDENING ───

	// 1. Set the absolute ceiling for open database handles.
	// If a 26th request comes in, Go will queue it safely instead of crashing Postgres.
	db.SetMaxOpenConns(25)

	// 2. Set the background standby cache limit.
	// Keeping this equal to MaxOpenConns prevents Go from constantly opening/closing connections.
	db.SetMaxIdleConns(25)

	// 3. Automatically recycle connections every 5 minutes.
	// This cleans up stale connections, handles network blips, and drops memory bloat.
	db.SetConnMaxLifetime(5 * time.Minute)

	// 4. Verify the connection pool is actually alive before returning
	if err := db.Ping(); err != nil {
		slog.Error("Database was reached, but ping failed", "error", err)
		os.Exit(1)
	}

	slog.Info("Database connection pool successfully initialized and hardened", "max_open", 25)
	return db
}

// InitializeApplication combines the logic to initialize all your layers
func InitializeApplication(db *sql.DB,rdb *redis.Client, secCfg api.SecurityConfig) (*api.AuthHandler, *api.HealthHandler, *api.MiddlewareManager) {
	authRepo := repository.NewPostgresRepository(db)
	authSvc := service.NewAuthService(authRepo)

	// 🚀 FIX: Convert the *redis.Client into your CacheManager interface implementation
	redisCache := config.NewRedisCache(rdb)
	authHdl := api.NewAuthHandler(authSvc, secCfg , redisCache)
	healthHdl := api.NewHealthHandler(db)

	middlewareMgr := api.NewMiddlewareManager(rdb)
	
	return authHdl, healthHdl, middlewareMgr
}

func StartServer(port string, handler http.Handler) {
	slog.Info("Server starting", "port", port)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}

// SetupRedisConnection initializes and pings your live WSL Redis server
func SetupRedisConnection() *redis.Client {
	// Points directly to your active local machine loopback port
	rdb := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:6379", 
	})

	// Run a high-priority boot probe to catch any configuration drops instantly
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		slog.Error("Failed to connect to Redis cache layer", "error", err)
		os.Exit(1)
	}

	slog.Info("Connected to Redis server successfully (PONG verified)")
	return rdb
}
