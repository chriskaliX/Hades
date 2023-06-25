package handler

import (
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"strconv"
)

type Bpf struct{}

var _ Event = (*Bpf)(nil)

func (c *Bpf) ID() int32 { return 3014 }

func (c *Bpf) Name() string { return "bpf" }

func (c *Bpf) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	mapper := make(map[string]interface{})
	// handle the data
	for k, v := range m {
		fv, err := strconv.ParseFloat(v, 64)
		if err == nil {
			mapper[k] = fv
		} else {
			mapper[k] = v
		}
	}

	DefaultWorker.Add(c.ID(), req.AgentID, mapper)
	return nil
}

func init() { RegistEvent(&Bpf{}) }
