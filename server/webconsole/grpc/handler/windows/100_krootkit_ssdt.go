package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KRootkitSsdt struct {
	Win_Rootkit_Ssdt_id         string `json:"win_rootkit_ssdt_id"`
	Win_Rootkit_Ssdt_offsetaddr string `json:"win_rootkit_ssdt_offsetaddr"`
}

func (k *KRootkitSsdt) ID() int32 { return 100 }

func (k *KRootkitSsdt) Name() string { return "kernel_rootkit_ssdt" }

func (c *KRootkitSsdt) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	err := json.Unmarshal([]byte(data), c)
	return err
}

func init() {
	handler.RegistEvent(&KRootkitSsdt{})
}
