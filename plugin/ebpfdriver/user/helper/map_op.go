package helper

import (
	"fmt"

	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
)

func MapUpdate(m *manager.Manager, name string, key uint32, value interface{}) error {
	bpfmap, found, err := m.GetMap(name)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("bpfmap %s not found", name)
	}
	return bpfmap.Update(key, value, ebpf.UpdateAny)
}
