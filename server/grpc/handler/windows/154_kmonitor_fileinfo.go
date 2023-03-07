package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KMonitorFileInfo struct {
	Win_SysMonitor_file_pid           string `json:"win_sysmonitor_file_pid"`
	Win_SysMonitor_file_tpid          string `json:"win_sysmonitor_file_tpid"`
	Win_SysMonitor_file_name          string `json:"win_sysmonitor_file_name"`
	Win_SysMonitor_file_dosname       string `json:"win_sysmonitor_file_dosname"`
	Win_SysMonitor_file_LockOperation string `json:"win_sysmonitor_file_LockOperation"`
	Win_SysMonitor_file_DeletePending string `json:"win_sysmonitor_file_DeletePending"`
	Win_SysMonitor_file_ReadAccess    string `json:"win_sysmonitor_file_ReadAccess"`
	Win_SysMonitor_file_WriteAccess   string `json:"win_sysmonitor_file_WriteAccess"`
	Win_SysMonitor_file_DeleteAccess  string `json:"win_sysmonitor_file_DeleteAccess"`
	Win_SysMonitor_file_SharedRead    string `json:"win_sysmonitor_file_SharedRead"`
	Win_SysMonitor_file_SharedWrite   string `json:"win_sysmonitor_file_SharedWrite"`
	Win_SysMonitor_file_SharedDelete  string `json:"win_sysmonitor_file_SharedDelete"`
	Win_SysMonitor_file_file_flag     string `json:"win_sysmonitor_file_flag"`
}

func (k *KMonitorFileInfo) ID() int32 { return 154 }

func (k *KMonitorFileInfo) Name() string { return "kernel_monitor_fileinfo" }

func (c *KMonitorFileInfo) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&KMonitorFileInfo{})
}
