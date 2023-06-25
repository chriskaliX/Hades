package handler

import (
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"strconv"
)

type SystemdUnit struct{}

var _ Event = (*SystemdUnit)(nil)

func (c *SystemdUnit) ID() int32 { return 3011 }

func (c *SystemdUnit) Name() string { return "systemd_unit" }

func (c *SystemdUnit) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
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

func init() { RegistEvent(&SystemdUnit{}) }
