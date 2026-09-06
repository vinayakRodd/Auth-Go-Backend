package config

import (
	"context"
	"time"
	"github.com/redis/go-redis/v9"
)

// RedisCache implements api.CacheManager using a real Redis Client
type RedisCache struct {
	client *redis.Client
}

func NewRedisCache(client *redis.Client) *RedisCache {
	return &RedisCache{client: client}
}

// Set stores the token with its TTL expiration window
func (r *RedisCache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

// Get fetches the data associated with a token string
func (r *RedisCache) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, key).Result()
}

// Incr atomically increments the integer counter stored at key, creating it
// (starting from 1) if it doesn't exist yet.
func (r *RedisCache) Incr(ctx context.Context, key string) (int64, error) {
	return r.client.Incr(ctx, key).Result()
}

// Expire sets (or refreshes) the TTL on an existing key.
func (r *RedisCache) Expire(ctx context.Context, key string, expiration time.Duration) error {
	return r.client.Expire(ctx, key, expiration).Err()
}

// Delete removes a key outright, e.g. to reset a counter.
func (r *RedisCache) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}