/*
 * This file contains the filters of Hades eBPF prog.
 * Since string prefix is limited in eBPF prog, we move string filter
 * part to userspace while filters like ip or id like BPF_MAP remained
 * in kernel space.
 */
package filter

import (
	"hades-ebpf/userspace/decoder"
	"strings"
	"sync"
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

var DefaultFilter Filter = Filter{}

func init() {
	DefaultFilter.kFilter = &KernelFilter{}
	DefaultFilter.uFilter = &UserFilter{}
	DefaultFilter.uFilter.Init()
}

/*
 * Filter defination
 */
type Filter struct {
	kFilter *KernelFilter
	uFilter *UserFilter
}

const (
	Update = iota
	Delete

	PidFilter      = "pid_filter"
	CgroupIdFilter = "cgroup_id_filter"
	IpFilter       = "ip_filter" /* struct Cidr with only CO-RE enabled */
)

/*
 * Action with the kernel space filter
 */

type KernelFilter struct{}

type Cidr struct {
	PrefixLen uint32
	Ip        uint32
}

func (f *KernelFilter) Set(m *manager.Manager, name string, key interface{}) (err error) {
	var _map *ebpf.Map
	_map, err = decoder.GetMap(m, name)
	if err != nil {
		return
	}
	var value uint32 = 0
	err = _map.Update(unsafe.Pointer(&key), unsafe.Pointer(&value), ebpf.UpdateAny)
	return
}

func (f *KernelFilter) Delete(m *manager.Manager, name string, key interface{}) (err error) {
	var _map *ebpf.Map
	_map, err = decoder.GetMap(m, name)
	if err != nil {
		return
	}
	err = _map.Delete(unsafe.Pointer(&key))
	return
}

func (f *KernelFilter) Get(m *manager.Manager, name string) (results []interface{}, err error) {
	var _map *ebpf.Map
	_map, err = decoder.GetMap(m, name)
	if err != nil {
		return
	}
	iter := _map.Iterate()
	var key, value interface{}
	/*
	 * The size is limited in kernel space,
	 */
	for iter.Next(key, value) {
		results = append(results, key)
	}
	return
}

/*
 * Userspace filter
 * This is a demo for all filters. Add other filters into this
 * if you need.
 */
const (
	ExeFilter = iota
	PathFilter
)

type UserFilter struct {
	ExeFilter  *sync.Map
	PathFilter *sync.Map
	once       sync.Once
}

const (
	Prefix = iota
	Suffix
	Equal
	Contains
)

type StringFilter struct {
	Operation int
	Value     string
}

func (u *UserFilter) FilterOut(in string) (result bool) {
	u.ExeFilter.Range(func(_key interface{}, _ interface{}) bool {
		filter := _key.(StringFilter)
		switch filter.Operation {
		case Prefix:
			result = strings.HasPrefix(in, filter.Value)
		case Suffix:
			result = strings.HasSuffix(in, filter.Value)
		case Equal:
			result = strings.EqualFold(in, filter.Value)
		case Contains:
			result = strings.Contains(in, filter.Value)
		default:
			return false
		}
		/*
		 * Stop if it's done
		 */
		if result {
			return false
		}
		return true
	})
	return
}

func (u *UserFilter) Init() {
	u.once.Do(func() {
		u.ExeFilter = &sync.Map{}
		u.PathFilter = &sync.Map{}
	})
}

func (u *UserFilter) Set(_type, int, op int, value string) {
	s := StringFilter{
		Operation: op,
		Value:     value,
	}
	switch _type {
	case ExeFilter:
		u.ExeFilter.Store(s, true)
	case PathFilter:
		u.PathFilter.Store(s, true)
	}
}

func (u *UserFilter) Delete(_type int, op int, value string) {
	var _map *sync.Map
	switch _type {
	case ExeFilter:
		_map = u.ExeFilter
	case PathFilter:
		_map = u.PathFilter
	}

	_map.Range(func(_key interface{}, _ interface{}) bool {
		filter := _key.(StringFilter)
		if filter.Operation == op && filter.Value == value {
			_map.Delete(_key)
			return false
		}
		return true
	})
}
