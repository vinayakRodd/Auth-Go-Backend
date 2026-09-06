package api

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"
)

var errNotFound = errors.New("key not found")

// fakeCache is a minimal in-memory CacheManager used to test the
// login-lockout logic without a real Redis instance.
type fakeCache struct {
	counters map[string]int64
	expires  map[string]time.Duration
	deleted  []string
}

func newFakeCache() *fakeCache {
	return &fakeCache{counters: make(map[string]int64), expires: make(map[string]time.Duration)}
}

func (c *fakeCache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return nil
}

func (c *fakeCache) Get(ctx context.Context, key string) (string, error) {
	v, ok := c.counters[key]
	if !ok {
		return "", errNotFound
	}
	return strconv.FormatInt(v, 10), nil
}

func (c *fakeCache) Incr(ctx context.Context, key string) (int64, error) {
	c.counters[key]++
	return c.counters[key], nil
}

func (c *fakeCache) Expire(ctx context.Context, key string, expiration time.Duration) error {
	c.expires[key] = expiration
	return nil
}

func (c *fakeCache) Delete(ctx context.Context, key string) error {
	delete(c.counters, key)
	c.deleted = append(c.deleted, key)
	return nil
}

func TestIsLoginLockedWithNoRecordedAttemptsIsNotLocked(t *testing.T) {
	h := &AuthHandler{cache: newFakeCache()}

	locked, err := h.isLoginLocked(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("isLoginLocked() error = %v", err)
	}
	if locked {
		t.Error("expected account with no failed attempts to not be locked")
	}
}

func TestRecordFailedLoginLocksAccountAfterThreshold(t *testing.T) {
	h := &AuthHandler{cache: newFakeCache()}
	ctx := context.Background()
	email := "user@example.com"

	for i := 0; i < maxFailedLoginAttempts-1; i++ {
		h.recordFailedLogin(ctx, email)
		locked, err := h.isLoginLocked(ctx, email)
		if err != nil {
			t.Fatalf("isLoginLocked() error = %v", err)
		}
		if locked {
			t.Fatalf("account locked too early, after %d attempts", i+1)
		}
	}

	h.recordFailedLogin(ctx, email)
	locked, err := h.isLoginLocked(ctx, email)
	if err != nil {
		t.Fatalf("isLoginLocked() error = %v", err)
	}
	if !locked {
		t.Errorf("expected account to be locked after %d failed attempts", maxFailedLoginAttempts)
	}
}

func TestClearFailedLoginsResetsCounter(t *testing.T) {
	h := &AuthHandler{cache: newFakeCache()}
	ctx := context.Background()
	email := "user@example.com"

	for i := 0; i < maxFailedLoginAttempts; i++ {
		h.recordFailedLogin(ctx, email)
	}
	h.clearFailedLogins(ctx, email)

	locked, err := h.isLoginLocked(ctx, email)
	if err != nil {
		t.Fatalf("isLoginLocked() error = %v", err)
	}
	if locked {
		t.Error("expected account to be unlocked after clearFailedLogins")
	}
}

func TestRecordFailedLoginIsIndependentPerAccount(t *testing.T) {
	h := &AuthHandler{cache: newFakeCache()}
	ctx := context.Background()

	for i := 0; i < maxFailedLoginAttempts; i++ {
		h.recordFailedLogin(ctx, "victim@example.com")
	}

	locked, err := h.isLoginLocked(ctx, "other@example.com")
	if err != nil {
		t.Fatalf("isLoginLocked() error = %v", err)
	}
	if locked {
		t.Error("a different account's failed attempts must not lock this one")
	}
}
