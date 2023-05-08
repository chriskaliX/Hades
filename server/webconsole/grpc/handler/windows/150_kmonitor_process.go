package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KMonitorProcess struct {
	Win_SysMonitor_process_parentpid        string `json:"win_sysmonitor_process_parentpid"`
	Win_SysMonitor_process_pid              string `json:"win_sysmonitor_process_pid"`
	Win_SysMonitor_process_endprocess       string `json:"win_sysmonitor_process_endprocess"`
	Win_SysMonitor_process_queryprocesspath string `json:"win_sysmonitor_process_queryprocesspath"`
	Win_SysMonitor_process_processpath      string `json:"win_sysmonitor_process_processpath"`
	Win_SysMonitor_process_commandLine      string `json:"win_sysmonitor_process_commandLine"`
}

func (k *KMonitorProcess) ID() int32 { return 150 }

func (k *KMonitorProcess) Name() string { return "kernel_monitor_process" }

func (c *KMonitorProcess) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&KMonitorProcess{})
}
