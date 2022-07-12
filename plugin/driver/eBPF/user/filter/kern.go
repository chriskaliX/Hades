package filter

import (
	"hades-ebpf/user/decoder"
	"unsafe"

	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
)

type KernelFilter struct{}

func (filter *KernelFilter) Set(m *manager.Manager, name string, key interface{}) (err error) {
	var _map *ebpf.Map
	_map, err = decoder.GetMap(m, name)
	if err != nil {
		return
	}
	var value uint32 = 0
	err = _map.Update(unsafe.Pointer(&key), unsafe.Pointer(&value), ebpf.UpdateAny)
	return
}

func (filter *KernelFilter) Delete(m *manager.Manager, name string, key interface{}) (err error) {
	var _map *ebpf.Map
	_map, err = decoder.GetMap(m, name)
	if err != nil {
		return
	}
	err = _map.Delete(unsafe.Pointer(&key))
	return
}

func (filter *KernelFilter) Get(m *manager.Manager, name string) (results []interface{}, err error) {
	var _map *ebpf.Map
	_map, err = decoder.GetMap(m, name)
	if err != nil {
		return
	}
	var key, value interface{}
	for _map.Iterate().Next(key, value) {
		results = append(results, key)
	}
	return
}
