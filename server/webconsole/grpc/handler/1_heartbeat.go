package handler

import (
	"context"
	"hboat/grpc/handler/subhandle"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"hboat/pkg/basic/mongo"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Heartbeat struct{}

var _ Event = (*Heartbeat)(nil)

func (h *Heartbeat) ID() int32 { return 1 }

func (h *Heartbeat) Name() string { return "heartbeat" }

func (h *Heartbeat) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	intranet_ipv4 := strings.Join(req.IntranetIPv4, ",")
	intranet_ipv6 := strings.Join(req.IntranetIPv6, ",")
	extranet_ipv4 := strings.Join(req.ExtranetIPv4, ",")
	extranet_ipv6 := strings.Join(req.ExtranetIPv6, ",")
	data := make(map[string]interface{}, 40)
	data["intranet_ipv4"] = intranet_ipv4
	data["intranet_ipv6"] = intranet_ipv6
	data["extranet_ipv4"] = extranet_ipv4
	data["extranet_ipv6"] = extranet_ipv6
	data["product"] = req.Product
	data["hostname"] = req.Hostname
	data["version"] = req.Version
	for k, v := range m {
		switch k {
		case "platform_version", "version":
			data[k] = v
		default:
			fv, err := strconv.ParseFloat(v, 64)
			if err == nil {
				data[k] = fv
			} else {
				data[k] = v
			}
		}
	}
	conn.LastHBTime = time.Now().Unix()
	if _, err := mongo.MongoProxyImpl.StatusC.UpdateOne(context.Background(), bson.M{"agent_id": req.AgentID},
		bson.M{"$set": bson.M{"agent_detail": data, "last_heartbeat_time": conn.LastHBTime}}); err != nil {
		return err
	}
	conn.SetAgentDetail(data)
	docs := bson.D{
		primitive.E{
			Key: "metrics",
			Value: bson.D{
				primitive.E{Key: "sys_cpu", Value: data["sys_cpu"]},
				primitive.E{Key: "agent_cpu", Value: data["cpu"]},
				primitive.E{Key: "sys_mem", Value: data["sys_mem"]},
				primitive.E{Key: "agent_mem", Value: data["rss"]},
			},
		},
		primitive.E{
			Key:   "type",
			Value: subhandle.AgentType,
		},
		primitive.E{
			Key:   "timestamp",
			Value: time.Now().UTC(),
		},
		primitive.E{
			Key:   "agent_id",
			Value: req.AgentID,
		},
	}
	DefaultWorker.AddMetric(docs)
	return nil
}

func init() {
	RegistEvent(&Heartbeat{})
}
