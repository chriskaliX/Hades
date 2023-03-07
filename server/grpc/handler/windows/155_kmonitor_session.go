package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KMonitorSession struct {
	Win_SysMonitor_session_pid       string `json:"win_sysmonitor_session_pid"`
	Win_SysMonitor_session_tpid      string `json:"win_sysmonitor_session_tpid"`
	Win_SysMonitor_session_event     string `json:"win_sysmonitor_session_event"`
	Win_SysMonitor_session_sessionid string `json:"win_sysmonitor_session_sessionid"`
}

func (k *KMonitorSession) ID() int32 { return 155 }

func (k *KMonitorSession) Name() string { return "kernel_monitor_session" }

func (c *KMonitorSession) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&KMonitorSession{})
}
