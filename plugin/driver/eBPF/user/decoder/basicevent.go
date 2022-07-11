// BasicEvent, optional functions with a default empty result, all Events
// are based on this for convenient
package decoder

import manager "github.com/ehids/ebpfmanager"

const emptyString = ""

type BasicEvent struct{}

func (BasicEvent) GetMaps() (result []*manager.Map) {
	result = make([]*manager.Map, 0)
	return
}

func (BasicEvent) GetExe() string {
	return emptyString
}
