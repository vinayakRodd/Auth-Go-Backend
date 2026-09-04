package api

import (
	"errors"
	"time"
)

const (

	ratelimitVal = 5
	max_bytes = 1048576 // 1 MB
	timeout_duration = 900 * time.Millisecond
)


var (

	TooManyRequestsError = errors.New("Too many requests. Please slow down.")
)
 

