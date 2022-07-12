package filter

import (
	"sync"
)

type UserFilter struct {
	ExeFilter  *sync.Map
	PathFilter *sync.Map
	once       sync.Once
}

func (filter *UserFilter) FilterOut(field int, in string) (result bool) {
	switch field {
	case ExeFilter:
		result = filter.rangeFilter(filter.ExeFilter, in)
	case PathFilter:
		result = filter.rangeFilter(filter.PathFilter, in)
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
	case PathFilter:
		filter.PathFilter.Store(s, true)
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

func (filter *UserFilter) rangeFilter(f *sync.Map, in string) (result bool) {
	if f == nil {
		return false
	}
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

func (filter *UserFilter) init() {
	filter.once.Do(func() {
		filter.ExeFilter = &sync.Map{}
		filter.PathFilter = &sync.Map{}
	})
}
