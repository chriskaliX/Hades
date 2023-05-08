package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KRootkitSysMod struct {
	Win_Rootkit_SysMod_DllBase     string `json:"win_rootkit_sys_DllBase"`
	Win_Rootkit_SysMod_FullDllName string `json:"win_rootkit_sys_FullDllName"`
}

func (k *KRootkitSysMod) ID() int32 { return 115 }

func (k *KRootkitSysMod) Name() string { return "kernel_rootkit_sysmod" }

func (c *KRootkitSysMod) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&KRootkitSysMod{})
}
