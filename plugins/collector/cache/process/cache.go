package process

import (
	"sync"

	"k8s.io/utils/lru"
)

const maxArgv = 2048
const maxPid = 4096

var PidCache = lru.New(maxPid)
var ArgvCache = lru.New(maxArgv)
var CmdlineCache = lru.New(maxPid)

var Pool = NewPool()

type ProcessPool struct {
	p sync.Pool
}

func NewPool() *ProcessPool {
	return &ProcessPool{
		p: sync.Pool{
			New: func() interface{} {
				return &Process{}
			},
		}}
}

func (p *ProcessPool) Get() *Process {
	pr := p.p.Get().(*Process)
	pr.reset()
	return pr
}

func (p *ProcessPool) Put(pr *Process) {
	p.p.Put(pr)
}
