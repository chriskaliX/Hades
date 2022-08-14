package filter

import (
	"fmt"
	"reflect"
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
	once       sync.Once
}

func NewUserFilter() *UserFilter {
	return &UserFilter{
		ExeFilter:  &sync.Map{},
		DnsFilter:  &sync.Map{},
		ArgvFilter: &sync.Map{},
	}
}

func (filter *UserFilter) FilterOut(field int, in string) (result bool) {
	switch field {
	case ExeFilter:
		result = filter.rangeFilter(filter.ExeFilter, in)
	case DnsFilter:
		result = filter.rangeFilter(filter.DnsFilter, in)
	case ArgvFilter:
		result = filter.rangeFilter(filter.ArgvFilter, in)
	}
	return false
}

func (filter *UserFilter) Set(_type, int, op int, value string) {
	s := StringFilter{
		Operation: op,
		Value:     value,
	}
	switch _type {
	case ExeFilter:
		filter.ExeFilter.Store(s, true)
	case DnsFilter:
		filter.DnsFilter.Store(s, true)
	case ArgvFilter:
		filter.ArgvFilter.Store(s, true)
	}
}

func (u *UserFilter) Delete(_type int, op int, value string) {
	var _map *sync.Map
	switch _type {
	case ExeFilter:
		_map = u.ExeFilter
	case DnsFilter:
		_map = u.DnsFilter
	case ArgvFilter:
		_map = u.ArgvFilter
	}
	// Delete the filter
	_map.Range(func(_key interface{}, _ interface{}) bool {
		filter := _key.(StringFilter)
		if filter.Operation == op && filter.Value == value {
			_map.Delete(_key)
			return false
		}
		return true
	})
}

// TODO: unfinished
func (u *UserFilter) Load(filterConfig *FilterConfig) {
	t := reflect.TypeOf(filterConfig).Elem()
	v := reflect.ValueOf(filterConfig).Elem()
	// go range the filter type
	for i := 0; i < t.NumField(); i++ {
		// only get slice
		if v.Field(i).Kind() != reflect.Slice {
			continue
		}
		_type := t.Field(i).Tag.Get("json")
		for index := 0; index < v.Field(i).Len(); index++ {
			fmt.Println(_type, v.Field(i).Index(index).String())
			switch _type {
			case "exe":
			case "dns":
			case "argv":
			}
		}
	}
}

func (filter *UserFilter) rangeFilter(f *sync.Map, in string) (result bool) {
	f.Range(func(_key interface{}, _ interface{}) bool {
		filter := _key.(StringFilter)
		result = filter.FilterOut(in)
		if result {
			return false
		}
		return true
	})
	return false
}
