/*
 * This file contains the filters of Hades eBPF prog.
 * Since string prefix is limited in eBPF prog, we move string filter
 * part to userspace while filters like ip or id like BPF_MAP remained
 * in kernel space.
 */
package filter

import (
	"strings"
	"sync"
)

var filteronce sync.Once

// Filter is the driver filter to filter out both kernel and space data.
// In Elkeid ,the dynamic filter seems a great idea for me. It works in
// a window like we does in Flink
type Filter struct {
	// User space field
	Exe  sync.Map
	Path sync.Map
	Dns  sync.Map
	Argv sync.Map
}

const (
	PidFilter      = "pid_filter"
	CgroupIdFilter = "cgroup_id_filter"
	IpFilter       = "ip_filter"
)

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

func (filter *StringFilter) FilterOut(in string) (result bool) {
	switch filter.Operation {
	case Prefix:
		result = strings.HasPrefix(in, filter.Value)
	case Suffix:
		result = strings.HasSuffix(in, filter.Value)
	case Equal:
		result = strings.EqualFold(in, filter.Value)
	case Contains:
		result = strings.Contains(in, filter.Value)
	}
	return result
}
