package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KMonitorThread struct {
	Win_SysMonitor_thread_pid    string `json:"win_sysmonitor_thread_pid"`
	Win_SysMonitor_thread_id     string `json:"win_sysmonitor_thread_id"`
	Win_SysMonitor_thread_status string `json:"win_sysmonitor_thread_status"`
}

func (k *KMonitorThread) ID() int32 { return 151 }

func (k *KMonitorThread) Name() string { return "kernel_monitor_thread" }

func (c *KMonitorThread) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	err := json.Unmarshal([]byte(data), c)
	return err
}

func init() {
	handler.RegistEvent(&KMonitorThread{})
}
