package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KRootkitProcessMod struct {
	Win_Rootkit_ProcessMod_pid         string `json:"win_rootkit_processmod_pid"`
	Win_Rootkit_ProcessMod_DllBase     string `json:"win_rootkit_process_DllBase"`
	Win_Rootkit_ProcessMod_SizeofImage string `json:"win_rootkit_process_SizeofImage"`
	Win_Rootkit_ProcessMod_EntryPoint  string `json:"win_rootkit_process_EntryPoint"`
	Win_Rootkit_ProcessMod_BaseDllName string `json:"win_rootkit_process_BaseDllName"`
	Win_Rootkit_ProcessMod_FullDllName string `json:"win_rootkit_process_FullDllName"`
}

func (k *KRootkitProcessMod) ID() int32 { return 113 }

func (k *KRootkitProcessMod) Name() string { return "kernel_rootkit_processmod" }

func (c *KRootkitProcessMod) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&KRootkitProcessMod{})
}
