package handler

import (
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"strconv"
)

type Process struct{}

var _ Event = (*Process)(nil)

func (p *Process) ID() int32 { return 1001 }

func (c *Process) Name() string { return "processes" }

func (c *Process) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	mapper := make(map[string]interface{})
	// handle the data
	for k, v := range m {
		switch k {
		case "pid", "root_pns", "pns", "gid", "pgid", "tid", "session_id", "ppid", "tty":
			i, _ := strconv.ParseUint(v, 10, 32)
			mapper[k] = i
		case "starttime", "utime", "stime", "rss", "vsize", "start_time":
			i, _ := strconv.ParseUint(v, 10, 64)
			mapper[k] = i
		case "cpu":
			i, _ := strconv.ParseFloat(v, 64)
			mapper[k] = i
		default:
			mapper[k] = v
		}
	}
	DefaultWorker.Add(c.ID(), req.AgentID, mapper)
	return nil
}

func init() { RegistEvent(&Process{}) }
