package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KMonitorInject struct {
	Win_Sysmonitor_inject_srcpid  string `json:"win_sysmonitor_inject_srcpid"`
	Win_Sysmonitor_inject_dstpid  string `json:"win_sysmonitor_inject_dstpid"`
	Win_Sysmonitor_inject_srcPath string `json:"win_sysmonitor_inject_srcPath"`
	Win_Sysmonitor_inject_dstPath string `json:"win_sysmonitor_inject_dstPath"`
}

func (k *KMonitorInject) ID() int32 { return 156 }

func (k *KMonitorInject) Name() string { return "kernel_monitor_inject" }

func (c *KMonitorInject) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&KMonitorInject{})
}
