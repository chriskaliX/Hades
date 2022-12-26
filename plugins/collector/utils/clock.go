package utils

import (
	"time"

	"github.com/chriskaliX/SDK/clock"
)

var Clock = clock.New(100 * time.Microsecond)
