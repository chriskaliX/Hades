/*
 * This file contains the filters of Hades eBPF prog.
 * Since string prefix is limited in eBPF prog, we move string filter
 * part to userspace while filters like ip or id like BPF_MAP remained
 * in kernel space.
 */
package filter

import "strings"

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

var DefaultFilter *Filter = NewFilter()

func NewFilter() *Filter {
	filter := &Filter{}
	filter.KernFilter = &KernelFilter{}
	filter.UserFilter = &UserFilter{}
	filter.UserFilter.init()
	return filter
}

/*
 * Filter defination
 */
type Filter struct {
	KernFilter *KernelFilter
	UserFilter *UserFilter
}

const (
	Update = iota
	Delete

	PidFilter      = "pid_filter"
	CgroupIdFilter = "cgroup_id_filter"
	IpFilter       = "ip_filter" /* struct Cidr with only CO-RE enabled */
)

/*
 * Userspace filter
 * This is a demo for all filters. Add other filters into this
 * if you need.
 */
const (
	ExeFilter = iota
	PathFilter
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
