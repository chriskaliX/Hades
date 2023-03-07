package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KRootkitProcessInfo struct {
	Win_Rootkit_Process_pid  string `json:"win_rootkit_process_pid"`
	Win_Rootkit_Process_Info string `json:"win_rootkit_process_info"`
}

func (k *KRootkitProcessInfo) ID() int32 { return 111 }

func (k *KRootkitProcessInfo) Name() string { return "kernel_rootkit_processinfo" }

func (c *KRootkitProcessInfo) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&KRootkitProcessInfo{})
}
