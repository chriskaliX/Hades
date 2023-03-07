package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KRootkitIdt struct {
	Win_Rootkit_Idt_id         string `json:"win_rootkit_idt_id"`
	Win_Rootkit_Idt_offsetaddr string `json:"win_rootkit_idt_offsetaddr"`
}

func (k *KRootkitIdt) ID() int32 { return 101 }

func (k *KRootkitIdt) Name() string { return "kernel_rootkit_idt" }

func (c *KRootkitIdt) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	err := json.Unmarshal([]byte(data), c)
	return err
}

func init() {
	handler.RegistEvent(&KRootkitIdt{})
}
