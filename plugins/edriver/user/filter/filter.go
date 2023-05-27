package filter

import (
	"encoding/json"
	"sync"

	"github.com/chriskaliX/SDK/transport/protocol"
	"golang.org/x/exp/slices"
)

// Filter configuration received by the task
// The format of the filter like this:
type FilterConfig struct {
	ExeList  []string `json:"exe"`
	DnsList  []string `json:"dns"`
	ArgvList []string `json:"argv"`
}

// Load the configuration from task
func LoadConfigFromTask(t *protocol.Task) (err error) {
	filterConfig := &FilterConfig{}
	if err = json.Unmarshal([]byte(t.GetData()), filterConfig); err != nil {
		return
	}
	// load every field
	if err = load(DefaultUserFilter.ArgvFilter, filterConfig.ArgvList); err != nil {
		return
	}
	if err = load(DefaultUserFilter.DnsFilter, filterConfig.DnsList); err != nil {
		return
	}
	if err = load(DefaultUserFilter.ExeFilter, filterConfig.ExeList); err != nil {
		return
	}
	return
}

func load(m *sync.Map, newList []string) (err error) {
	if m == nil {
		return
	}
	// remove firstly
	m.Range(func(key any, _ any) bool {
		if slices.Contains(newList, key.(string)) {
			index := slices.Index(newList, key.(string))
			newList = slices.Delete(newList, index, index+1)
			return true
		}
		m.Delete(key)
		return true
	})
	return
}
