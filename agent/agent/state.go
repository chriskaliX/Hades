// Agent state machine from Elkeid
// Add some trivial limitation
package agent

import (
	"encoding/json"
	"sync"
)

type StateType int32

const (
	StateTypeRunning StateType = iota
	StateTypeAbnormal
)

const (
	maxError     = 10
	maxErrorSize = 1024 * 1024
)

var stateTypeMap = map[StateType]string{
	StateTypeRunning:  "running",
	StateTypeAbnormal: "abnormal",
}

var (
	mu           sync.Mutex
	currentState = StateTypeRunning
	abnormalErrs = []string{} // max length should be set
)

func (x StateType) String() string {
	return stateTypeMap[x]
}

func SetRunning() {
	mu.Lock()
	defer mu.Unlock()
	currentState = StateTypeRunning
	abnormalErrs = []string{}
}

func SetAbnormal(err string) {
	mu.Lock()
	defer mu.Unlock()
	currentState = StateTypeAbnormal
	if len(err) > maxErrorSize {
		err = err[:maxErrorSize]
	}

	abnormalErrs = append(abnormalErrs, err)
	// Set the limitation of errors
	if len(abnormalErrs) > maxError {
		abnormalErrs = abnormalErrs[1:maxError]
	}
}

func State() (string, string) {
	mu.Lock()
	defer mu.Unlock()
	err, _ := json.Marshal(abnormalErrs)
	return currentState.String(), string(err)
}
