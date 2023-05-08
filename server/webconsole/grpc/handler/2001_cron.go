package handler

import (
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"strconv"
)

type Cron struct{}

var _ Event = (*Cron)(nil)

func (c *Cron) ID() int32 { return 2001 }

func (c *Cron) Name() string { return "crons" }

func (c *Cron) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	mapper := make(map[string]interface{})
	// handle the data
	for k, v := range m {
		switch k {
		case "minute", "hour", "day_of_month", "month", "day_of_week":
			i, _ := strconv.ParseUint(v, 10, 32)
			mapper[k] = i
		default:
			mapper[k] = v
		}
	}
	DefaultWorker.Add(c.ID(), req.AgentID, mapper)
	return nil
}

func init() { RegistEvent(&Cron{}) }
