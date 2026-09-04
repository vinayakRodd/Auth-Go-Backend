package main

import (
	
	"auth-go/internal/app"
	"auth-go/internal/api"
)

func main() {
	app.InitLogger()
	cfg := app.LoadConfig()
	rdb := app.SetupRedisConnection() 
	db := app.SetupDatabaseConnection(cfg.DBUrl)
	defer db.Close()

	// Initialization
	authHandler, healthHandler, middlewareHandler := app.InitializeApplication(db, rdb, cfg)

	// Routing
	handler := api.SetupRoutes(authHandler, healthHandler, middlewareHandler)

	// Start
	app.StartServer(cfg.Port, handler)
}