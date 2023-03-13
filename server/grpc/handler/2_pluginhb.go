package handler

import (
	"context"
	"hboat/pkg/basic/mongo"
	"strconv"
	"time"

	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"

	"go.mongodb.org/mongo-driver/bson"
)

type PluginHeartbeat struct{}

var _ Event = (*PluginHeartbeat)(nil)

func (p *PluginHeartbeat) ID() int32 { return 2 }

func (p *PluginHeartbeat) Name() string { return "plugin_heartbeat" }

func (p *PluginHeartbeat) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := make(map[string]interface{})
	for k, v := range m {
		// skip special field, hard-code
		if k == "pversion" {
			data[k] = v
			continue
		}
		fv, err := strconv.ParseFloat(v, 64)
		if err == nil {
			data[k] = fv
		} else {
			data[k] = v
		}
	}

	// No plugin is available, clear the plugin_detail
	if len(m) == 0 {
		_, err := mongo.StatusC.UpdateOne(
			context.Background(),
			bson.M{"agent_id": req.AgentID},
			bson.M{"$set": bson.M{"plugin_detail": map[string]string{}}})
		return err
	}

	// Added heartbeat_time with plugin
	data["last_heartbeat_time"] = time.Now().Unix()
	_, err := mongo.StatusC.UpdateOne(context.Background(), bson.M{"agent_id": req.AgentID},
		bson.M{"$set": bson.M{"plugin_detail." + m["name"]: data}})
	conn.SetPluginDetail(data["name"].(string), data)
	return err
}

func init() { RegistEvent(&PluginHeartbeat{}) }
