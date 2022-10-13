package decoder

import (
	manager "github.com/ehids/ebpfmanager"
)

const defaultRet = "-1"

// BasicEvent implements the basic functions which are necessary
// of the Event with default return values
type BasicEvent struct {
	context *Context
}

func (BasicEvent) GetMaps() (result []*manager.Map) {
	result = make([]*manager.Map, 0)
	return
}

// GetExe return a default "-1" since in some Event like anti-rootkit
// field Exe is not collected
func (BasicEvent) GetExe() string {
	return defaultRet
}

func (BasicEvent) FillCache() {
	return
}

func (BasicEvent) RegistCron() (string, EventCronFunc) {
	return "", nil
}

// Context getter/setter
func (b *BasicEvent) SetContext(ctx *Context) {
	b.context = ctx
}

func (b *BasicEvent) Context() *Context {
	return b.context
}
