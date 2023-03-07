package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KMonitorMod struct {
	Win_SysMonitor_mod_pid      string `json:"win_sysmonitor_mod_pid"`
	Win_SysMonitor_mod_base     string `json:"win_sysmonitor_mod_base"`
	Win_SysMonitor_mod_size     string `json:"win_sysmonitor_mod_size"`
	Win_SysMonitor_mod_path     string `json:"win_sysmonitor_mod_path"`
	Win_SysMonitor_mod_sysimage string `json:"win_sysmonitor_mod_sysimage"`
}

func (k *KMonitorMod) ID() int32 { return 152 }

func (k *KMonitorMod) Name() string { return "kernel_monitor_mod" }

func (c *KMonitorMod) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	err := json.Unmarshal([]byte(data), c)
	return err
}

func init() {
	handler.RegistEvent(&KMonitorMod{})
}
