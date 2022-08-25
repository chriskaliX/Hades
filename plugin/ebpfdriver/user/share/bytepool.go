package share

import (
	"go.uber.org/zap/buffer"
)

var BufferPool buffer.Pool = buffer.NewPool()
