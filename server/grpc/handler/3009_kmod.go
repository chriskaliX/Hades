package handler

import (
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"strconv"
)

type Kmod struct{}

var _ Event = (*Container)(nil)

func (c *Kmod) ID() int32 { return 3009 }

func (c *Kmod) Name() string { return "kmods" }

func (c *Kmod) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	mapper := make(map[string]interface{})
	// handle the data
	for k, v := range m {
		switch k {
		case "size", "refcount":
			i, _ := strconv.ParseUint(v, 10, 64)
			mapper[k] = i
		default:
			mapper[k] = v
		}
	}
	DefaultWorker.Add(c.ID(), req.AgentID, mapper)
	return nil
}

func init() { RegistEvent(&Kmod{}) }
