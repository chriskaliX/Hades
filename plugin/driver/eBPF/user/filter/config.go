package filter

import (
	"encoding/json"

	"github.com/chriskaliX/plugin"
)

// Filter configuration received by the task
// The format of the filter like this:
// {"exelist": ["0/ps",...]}, index 0 string is the operation
type FilterConfig struct {
	ExeList  []string `json:"exe" hades:"0"`
	DnsList  []string `json:"dns" hades:"1"`
	ArgvList []string `json:"argv" hades:"2"`
}

// Load the configuration from task
func LoadConfigFromTask(t *plugin.Task) (*FilterConfig, error) {
	filterConfig := &FilterConfig{}
	err := json.Unmarshal([]byte(t.GetData()), filterConfig)
	if err != nil {
		return nil, err
	}
	return filterConfig, nil
}
