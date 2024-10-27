package handler

import (
	"fmt"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"strconv"
)

type EguardEgress struct{}

var _ Event = (*EguardEgress)(nil)

func (c *EguardEgress) ID() int32 { return 3200 }

func (c *EguardEgress) Name() string { return "egress" }

func (c *EguardEgress) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	mapper := make(map[string]interface{})
	// handle the data
	for k, v := range m {
		switch k {
		case "pid", "pns":
			i, _ := strconv.ParseUint(v, 10, 32)
			mapper[k] = i
		default:
			mapper[k] = v
		}
	}

	fmt.Println(mapper)
	return nil
}

func init() { RegistEvent(&EguardEgress{}) }
