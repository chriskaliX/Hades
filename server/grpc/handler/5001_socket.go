package handler

import (
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"strconv"
)

type Socket struct{}

var _ Event = (*Socket)(nil)

func (u *Socket) ID() int32 { return 5001 }

func (u *Socket) Name() string { return "sockets" }

func (c *Socket) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	mapper := make(map[string]interface{})
	// handle the data
	for k, v := range m {
		switch k {
		case "sport", "dport", "uid", "family", "interface", "state", "pid", "type":
			i, _ := strconv.ParseUint(v, 10, 32)
			mapper[k] = i
		case "inode":
			i, _ := strconv.ParseUint(v, 10, 64)
			mapper[k] = i
		default:
			mapper[k] = v
		}
	}
	DefaultWorker.Add(c.ID(), req.AgentID, mapper)
	return nil
}

func init() { RegistEvent(&Socket{}) }
