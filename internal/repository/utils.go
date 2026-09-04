// internal/repository/utils.go
package repository

import (
    "github.com/lib/pq"
	"log"
)

func handleDBError(err error) error {
    if err == nil { return nil }

    // Check for Postgres-specific errors
    if pgErr, ok := err.(*pq.Error); ok {
        switch pgErr.Code {
        case "23505": // Unique Violation
            return ErrEmailAlreadyExists
        default:
            log.Printf("DB Error: Code %s, Message: %s", pgErr.Code, pgErr.Message)
            return err // Return raw error for unhandled cases
        }
    }
    
    return err
}
