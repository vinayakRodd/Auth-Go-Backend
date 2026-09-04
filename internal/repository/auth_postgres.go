package repository

import (
    "context"
    "database/sql"
    "auth-go/internal/models"
    "errors"
)

type postgresRepo struct {
    db *sql.DB // variable and its type what it is going to hold
}

// NewPostgresRepository acts as a constructor for the Postgres repository, injecting the database connection.
func NewPostgresRepository(db *sql.DB) AuthRepository { // dependency injection of *sql.DB
    return &postgresRepo{db: db}
}


func (r *postgresRepo) CreateUser(ctx context.Context, user *models.User) error {
    query := "INSERT INTO users (email, password) VALUES ($1, $2)"
    
    _, err := r.db.ExecContext(ctx, query, user.Email, user.Password)
    if err != nil {
        return handleDBError(err)
    }

    return nil
}

func (r *postgresRepo) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
   
    user := &models.User{}
    query := "SELECT id, email, password, created_at FROM users WHERE email = $1"
    
    // 2. Execute context-aware row query
    row := r.db.QueryRowContext(ctx, query, email)
    
    // 3. Scan values out securely.
    // Ensure types like user.CreatedAt map correctly (e.g., using time.Time or sql.NullTime if nullable)
    err := row.Scan(&user.ID, &user.Email, &user.Password, &user.CreatedAt)
    if err != nil {
        // 4. Handle "Not Found" specifically (Decoupled domain error)
        if errors.Is(err, sql.ErrNoRows) {
            return nil, ErrNotFound 
        }
        
        
        // 6. Handle other DB errors safely
        return nil, handleDBError(err)
    }
    
    return user, nil
}


func (r *postgresRepo) UpdatePasswordByEmail(ctx context.Context, email string, password string) error {
    query := `UPDATE users SET password = $1 WHERE email = $2`
    
    // 1. Context-aware execution protects connection pools from hanging threads
    result, err := r.db.ExecContext(ctx, query, password, email)
    if err != nil {
        return handleDBError(err)
    }

    // 2. Check if the user actually existed to receive the update
    rowsAffected, err := result.RowsAffected()
    if err != nil {
        return handleDBError(err)
    }

    if rowsAffected == 0 {
        return ErrNotFound // 💡 FIXED: Uses the consistent domain error
    }
    
    return nil
}


func (r *postgresRepo) EmailExists(ctx context.Context, email string) (bool, error) {
    var exists bool
    query := `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`
    
    err := r.db.QueryRowContext(ctx, query, email).Scan(&exists)
    if err != nil {
        return false, handleDBError(err)
    }
    
    return exists, nil
}