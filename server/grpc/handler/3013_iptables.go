package handler

import (
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"strconv"
)

type Iptable struct{}

var _ Event = (*Iptable)(nil)

func (c *Iptable) ID() int32 { return 3013 }

func (c *Iptable) Name() string { return "iptables" }

func (c *Iptable) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
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

func init() { RegistEvent(&Iptable{}) }
