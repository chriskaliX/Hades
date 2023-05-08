package handler

import (
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"strconv"
)

type Container struct{}

var _ Event = (*Container)(nil)

func (c *Container) ID() int32 { return 3018 }

func (c *Container) Name() string { return "containers" }

func (c *Container) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	mapper := make(map[string]interface{})
	// handle the data
	for k, v := range m {
		switch k {
		case "pid", "pns":
			i, _ := strconv.ParseUint(v, 10, 32)
			mapper[k] = i
		// case "labels":
		// 	value := make(map[string]interface{})
		// 	json.Unmarshal([]byte(v), &value)
		// 	mapper[k] = value
		default:
			mapper[k] = v
		}
	}
	DefaultWorker.Add(c.ID(), req.AgentID, mapper)
	return nil
}

func init() { RegistEvent(&Container{}) }
