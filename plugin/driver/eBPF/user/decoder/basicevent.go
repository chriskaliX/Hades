// BasicEvent, optional functions with a default empty result, all Events
// are based on this for convenient
package decoder

import manager "github.com/ehids/ebpfmanager"

const defaultRet = "-1"

type BasicEvent struct{}

func (BasicEvent) GetMaps() (result []*manager.Map) {
	result = make([]*manager.Map, 0)
	return
}

func (BasicEvent) GetExe() string {
	return defaultRet
}

func (BasicEvent) FillContext(uint32) {
	return
}
