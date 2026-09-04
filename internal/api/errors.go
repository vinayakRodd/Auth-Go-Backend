package api

import (
	"errors"
	"time"
)

const (

	ratelimitVal = 5
	max_bytes = 1048576 // 1 MB
	timeout_duration = 900 * time.Millisecond

	// maxFailedLoginAttempts is how many consecutive wrong-password login
	// attempts a single account tolerates before it's temporarily locked,
	// independent of the per-IP rate limiter.
	maxFailedLoginAttempts = 5
	// loginLockoutWindow is both the failed-attempt counting window and the
	// lockout duration once maxFailedLoginAttempts is reached.
	loginLockoutWindow = 15 * time.Minute
)


var (

	TooManyRequestsError = errors.New("Too many requests. Please slow down.")
	AccountLockedError   = errors.New("Too many failed login attempts. Please try again later.")
)
 

