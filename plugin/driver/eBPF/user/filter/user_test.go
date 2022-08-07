package filter

import "testing"

func TestUser(t *testing.T) {
	filterConfig := &FilterConfig{
		ExeList: []string{"0ps"},
		DnsList: []string{"0.qq.com"},
	}
	userFilter := NewUserFilter()
	userFilter.Load(filterConfig)
}
