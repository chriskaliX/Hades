package handler

import (
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"strconv"
)

type App struct{}

var _ Event = (*Container)(nil)

func (c *App) ID() int32 { return 3008 }

func (c *App) Name() string { return "apps" }

func (c *App) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	mapper := make(map[string]interface{})
	// handle the data
	for k, v := range m {
		switch k {
		case "pid", "tid", "pgid", "pns", "root_pns", "uid", "gid":
			i, _ := strconv.ParseUint(v, 10, 32)
			mapper[k] = i
		case "start_time":
			i, _ := strconv.ParseUint(v, 10, 64)
			mapper[k] = i
		default:
			mapper[k] = v
		}
	}
	DefaultWorker.Add(c.ID(), req.AgentID, mapper)
	return nil
}

func init() { RegistEvent(&App{}) }
