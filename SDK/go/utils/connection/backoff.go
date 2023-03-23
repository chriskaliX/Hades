package connection

import (
	"math"
	"time"
)

var Inifity uint = math.MaxUint

// Backoff is based on https://github.com/grpc/grpc-go/blob/master/backoff/backoff.go
type Config struct {
	// BeforeDelay is the time to deley before the connection start
	BeforeDelay time.Duration
	// Multiplier is the factor with which to multiply backoffs after a
	// failed retry. Should ideally be greater than 1.
	Multiplier float64
	// MaxRetry is the upper bound of backoff retry.
	MaxRetry uint
	// MaxDelay is the upper bound of backoff delay.
	MaxDelaySec uint
}

var DefaultConfig = Config{
	BeforeDelay: 1.0 * time.Second,
	Multiplier:  3,
	MaxRetry:    10,
	MaxDelaySec: 120,
}
