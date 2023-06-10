package handler

import (
	"context"
	"fmt"
	"hboat/grpc/handler/subhandle"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"hboat/pkg/basic/mongo"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	mg "go.mongodb.org/mongo-driver/mongo"
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
	// Add metrics
	// agent_metrics format: sys_cpu, agent_cpu, sys_mem, agent_mem
	// docs := bson.D{{Key: "metrics", Value: fmt.Sprintf("%f,%f,%f,%f",
	// 	data["sys_cpu"],
	// 	data["agent_cpu"],
	// 	data["sys_mem"],
	// 	float64(data["rss"].(float64)/(1024*1024)))},
	// 	{Key: "agent_id", Value: req.AgentID},
	// 	{Key: "type", Value: subhandle.AgentType},
	// 	{Key: "timestamp", Value: primitive.NewDateTimeFromTime(time.Now().UTC())},
	// }
	docs := bson.M{
		"metrics": fmt.Sprintf("%f,%f,%f,%f",
			data["sys_cpu"],
			data["agent_cpu"],
			data["sys_mem"],
			float64(data["rss"].(float64)/(1024*1024))),
		"agent_id":  req.AgentID,
		"type":      subhandle.AgentType,
		"timestamp": primitive.NewDateTimeFromTime(time.Now().UTC()),
	}

	model := mg.NewInsertOneModel().SetDocument(docs)
	DefaultWorker.AddMetric(mg.NewInsertOneModel().SetDocument(model))
	return nil
}

func init() {
	RegistEvent(&Heartbeat{})
}
