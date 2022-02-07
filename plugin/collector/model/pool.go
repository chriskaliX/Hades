package model

import "sync"

var DefaultProcessPool = NewPool()

type ProcessPool struct {
	p *sync.Pool
}

func NewPool() *ProcessPool {
	return &ProcessPool{p: &sync.Pool{
		New: func() interface{} {
			return &Process{}
		},
	}}
}

func (p ProcessPool) Get() *Process {
	pr := p.p.Get().(*Process)
	pr.Reset()
	return pr
}

func (p ProcessPool) Put(pr *Process) {
	p.p.Put(pr)
}
