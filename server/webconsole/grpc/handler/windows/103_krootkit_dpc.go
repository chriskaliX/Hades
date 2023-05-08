package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KRootkitDpc struct {
	Win_Rootkit_Dpc             string `json:"win_rootkit_dpc"`
	Win_Rootkit_Dpc_timeobj     string `json:"win_rootkit_dpc_timeobj"`
	Win_Rootkit_Dpc_timeroutine string `json:"win_rootkit_dpc_timeroutine"`
	Win_Rootkit_Dpc_periodtime  string `json:"win_rootkit_dpc_periodtime"`
}

func (k *KRootkitDpc) ID() int32 { return 103 }

func (k *KRootkitDpc) Name() string { return "kernel_rootkit_drc" }

func (c *KRootkitDpc) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	err := json.Unmarshal([]byte(data), c)
	return err
}

func init() {
	handler.RegistEvent(&KRootkitDpc{})
}
