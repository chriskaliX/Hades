package decoder

import (
	"time"

	manager "github.com/ehids/ebpfmanager"
)

const defaultRet = "-1"

type BasicEvent struct {
	context *Context
}

func (BasicEvent) GetMaps() (result []*manager.Map) {
	result = make([]*manager.Map, 0)
	return
}

func (BasicEvent) GetExe() string {
	return defaultRet
}

func (BasicEvent) FillCache() {
	return
}

func (BasicEvent) RegistCron(time.Duration) {
	return
}

func (b *BasicEvent) SetContext(ctx *Context) {
	b.context = ctx
}

func (b *BasicEvent) Context() *Context {
	return b.context
}
