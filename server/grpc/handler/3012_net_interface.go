package handler

import (
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"strconv"
)

type NetInterface struct{}

var _ Event = (*NetInterface)(nil)

func (c *NetInterface) ID() int32 { return 3012 }

func (c *NetInterface) Name() string { return "net_interfaces" }

func (c *NetInterface) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
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
