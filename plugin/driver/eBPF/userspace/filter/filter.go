/*
 * This file contains the filters of Hades eBPF prog.
 * Since string prefix is limited in eBPF prog, we move string filter
 * part to userspace while filters like ip or id like BPF_MAP remained
 * in kernel space.
 */
package filter

import (
	"hades-ebpf/userspace/decoder"
	"unsafe"

	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
)

/*
 * There are the filters in Hades
 *
 * path_filter: filter for path
 * config_map : configuration, like PID
 * pid_filter : filter for pid
 * cgroup_id_filter
 * ipfilter   : filter for remote ip
 *
 * Other filters like exe filter or path filter
 * we'll archieve just in user space
 */

var DefaultFilter Filter

/*
 * Filter defination
 */
type Filter struct {
	kFilter *KernelFilter
	uFilter *UserFilter
}

type KernelFilter struct {
	PidFilter      map[interface{}]bool
	CgroupIdFilter map[interface{}]bool
	IpFilter       map[interface{}]bool
}

/*
 * TODO: prefix and suffix should be added
 */
type UserFilter struct {
	ExeFilter  map[string]bool
	PathFilter map[string]bool
}

type Cidr struct {
	PrefixLen uint32
	Ip        uint32
}

const (
	Update = iota
	Delete

	PathFilter     = "path_filter"
	PidFilter      = "pid_filter"
	CgroupIdFilter = "cgroup_id_filter"
	IpFilter       = "ip_filter" /* struct Cidr with only CO-RE enabled */
)

/*
 * Action with the kernel space filter
 */
func (f *Filter) DoKernelFilter(m *manager.Manager, name string, key interface{}, action int) (err error) {
	var _map *ebpf.Map
	_map, err = decoder.GetMap(m, name)
	if err != nil {
		return
	}
	var value uint32 = 0
	switch action {
	case Update:
		err = _map.Update(unsafe.Pointer(&key), unsafe.Pointer(&value), ebpf.UpdateAny)
	case Delete:
		err = _map.Delete(unsafe.Pointer(&key))
	}
	return
}
