package handler

import (
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"strconv"
)

type Jar struct{}

var _ Event = (*Jar)(nil)

func (c *Jar) ID() int32 { return 3015 }

func (c *Jar) Name() string { return "jars" }

func (c *Jar) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	mapper := make(map[string]interface{})
	// handle the data
	for k, v := range m {
		switch k {
		default:
			i, err := strconv.ParseUint(v, 10, 64)
			if err == nil {
				mapper[k] = i
			} else {
				mapper[k] = v
			}
		}
	}
	DefaultWorker.Add(c.ID(), req.AgentID, mapper)
	return nil
}

func init() { RegistEvent(&Jar{}) }
