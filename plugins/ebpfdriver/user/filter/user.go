// Userspace filter
package filter

import (
	"strings"
	"sync"
)

const (
	ExeFilter = iota
	DnsFilter
	ArgvFilter
)

type UserFilter struct {
	ExeFilter  *sync.Map
	DnsFilter  *sync.Map
	ArgvFilter *sync.Map
}

var DefaultUserFilter = NewUserFilter()

func NewUserFilter() *UserFilter {
	return &UserFilter{
		ExeFilter:  &sync.Map{},
		DnsFilter:  &sync.Map{},
		ArgvFilter: &sync.Map{},
	}
}

// true = pass
// false = do not pass
func (f *UserFilter) FilterOut(field int, in string) (result bool) {
	switch field {
	case ExeFilter:
		// exe filter
		_, ok := f.ExeFilter.Load(in)
		return !ok
	case DnsFilter:
		// dns filter
		result = true
		f.DnsFilter.Range(func(key any, _ any) bool {
			if strings.HasSuffix(in, key.(string)) {
				result = false
				return false
			}
			return true
		})
		return result
	case ArgvFilter:
		_, ok := f.ArgvFilter.Load(in)
		return !ok
	}
	return result
}

func (filter *UserFilter) Set(_type int, value string) {
	switch _type {
	case ExeFilter:
		filter.ExeFilter.Store(value, true)
	case DnsFilter:
		filter.DnsFilter.Store(value, true)
	case ArgvFilter:
		filter.ArgvFilter.Store(value, true)
	}
}
