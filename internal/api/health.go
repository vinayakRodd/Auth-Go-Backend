package api

import (
	"database/sql"
	"net/http"
	"log"
)

// HealthHandler holds dependencies like the database connection
type HealthHandler struct {
	db *sql.DB
}

func NewHealthHandler(db *sql.DB) *HealthHandler {
	return &HealthHandler{db: db}
}

func (h *HealthHandler) Check(w http.ResponseWriter, r *http.Request) {
    if err := h.db.Ping(); err != nil {
        // 1. Log the full error to your terminal (private)
        log.Printf("DEBUG: Database ping failed: %v", err)
        
        // 2. Return a generic, safe message to the client (public)
        w.WriteHeader(http.StatusServiceUnavailable)
        w.Write([]byte("Database Down")) 
        return
    }

    log.Printf("DEBUG: Database ping successful")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}