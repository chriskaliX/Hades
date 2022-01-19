package parser

import (
	"sync"
)

var bufPool *bufferPool

type bufferPool struct {
	pool sync.Pool
}

func init() {
	bufPool = newBufferPool()
}

func newBufferPool() *bufferPool {
	return &bufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 256)
			},
		},
	}
}

func (p *bufferPool) get() []byte {
	return p.pool.Get().([]byte)
}

func (p *bufferPool) put(b []byte) {
	p.pool.Put(b[0:])
}
