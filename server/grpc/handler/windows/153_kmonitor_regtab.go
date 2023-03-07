package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KMonitorRegtab struct {
	Win_SysMonitor_regtab_pid                 string `json:"win_sysmonitor_regtab_pid"`
	Win_SysMonitor_regtab_tpid                string `json:"win_sysmonitor_regtab_tpid"`
	Win_SysMonitor_regtab_opeares             string `json:"win_sysmonitor_regtab_opeares"`
	Win_sysmonitor_regtab_processPath         string `json:"win_sysmonitor_regtab_processPath"`
	Win_sysmonitor_regtab_rootobject          string `json:"win_sysmonitor_regtab_rootobject"`
	Win_sysmonitor_regtab_object              string `json:"win_sysmonitor_regtab_object"`
	Win_sysmonitor_regtab_type                string `json:"win_sysmonitor_regtab_type"`
	Win_sysmonitor_regtab_attributes          string `json:"win_sysmonitor_regtab_attributes"`
	Win_sysmonitor_regtab_desiredAccess       string `json:"win_sysmonitor_regtab_desiredAccess"`
	Win_sysmonitor_regtab_disposition         string `json:"win_sysmonitor_regtab_disposition"`
	Win_sysmonitor_regtab_grantedAccess       string `json:"win_sysmonitor_regtab_grantedAccess"`
	Win_sysmonitor_regtab_options             string `json:"win_sysmonitor_regtab_options"`
	Win_sysmonitor_regtab_wow64Flags          string `json:"win_sysmonitor_regtab_wow64Flags"`
	Win_sysmonitor_regtab_keyInformationClass string `json:"win_sysmonitor_regtab_keyInformationClass"`
	Win_sysmonitor_regtab_index               string `json:"win_sysmonitor_regtab_index"`
	Win_sysmonitor_regtab_completeName        string `json:"win_sysmonitor_regtab_completeName"`
}

func (k *KMonitorRegtab) ID() int32 { return 153 }

func (k *KMonitorRegtab) Name() string { return "kernel_monitor_regtab" }

func (c *KMonitorRegtab) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	err := json.Unmarshal([]byte(data), c)
	return err
}

func init() {
	handler.RegistEvent(&KMonitorRegtab{})
}
