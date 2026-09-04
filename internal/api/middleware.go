package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"github.com/redis/go-redis/v9"
)

// 1. DEFINE THE STRUCT (This is what Go says is undefined!)
type MiddlewareManager struct {
	rdb *redis.Client
}

// 2. DEFINE THE CONSTRUCTOR
func NewMiddlewareManager(rdb *redis.Client) *MiddlewareManager {
	return &MiddlewareManager{rdb: rdb}
}

func (m *MiddlewareManager) RateLimit(maxRequests int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// 1. Clean IP extraction
			ip := r.RemoteAddr
			if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
				ip = strings.Split(prior, ",")[0]
			}
			redisKey := fmt.Sprintf("rate:%s", ip)

			// 2. INDUSTRY STANDARD: Atomic Pipeline (Fixes an edge-case expiration race condition)
			// We use a Redis pipeline or transaction to INCR and EXPIRE at the exact same time
			pipe := m.rdb.Pipeline()
			incr := pipe.Incr(ctx, redisKey)
			pipe.TTL(ctx, redisKey) // Check how long this key has left to live
			
			_, err := pipe.Exec(ctx)
			if err != nil {
				next.ServeHTTP(w, r) // Fail-open
				return
			}

			count := incr.Val()

			// 3. Set expiration only if the key was just created (-1 means no TTL set)
			if count == 1 {
				m.rdb.Expire(ctx, redisKey, window)
			}

			// 4. Guard Clause: Fast error escape
			if count > int64(maxRequests) {
				respondWithJSON(w, http.StatusTooManyRequests, map[string]string{
					"error": TooManyRequestsError.Error(),
				})
				return // Keep this! It's the cleanest way to stop execution cleanly.
			}

			next.ServeHTTP(w, r)
		})
	}
}


func enableCORS(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Allow your Next.js application origin
        w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
        w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
        w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
        w.Header().Set("Access-Control-Allow-Credentials", "true")

        // 💡 CRITICAL: Intercept the browser's automatic Preflight request
        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusNoContent)
            return
        }

        next.ServeHTTP(w, r)
    })
}
