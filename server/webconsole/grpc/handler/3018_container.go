package handler

import (
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"strconv"
	"strings"
)

type Container struct{}

const imgName = "image_name"

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
		default:
			mapper[k] = v
		}
	}
	// extract the real name and version
	name, ok := mapper[imgName].(string)
	if ok {
		arr := strings.Split(name, ":")
		mapper["image_name_without_version"] = arr[0]
	} else {
		mapper["image_name_without_version"] = ""
	}

	DefaultWorker.Add(c.ID(), req.AgentID, mapper)
	return nil
}

func init() { RegistEvent(&Container{}) }
