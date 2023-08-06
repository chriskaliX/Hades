package host

import (
	"context"
	"encoding/json"
	"hboat/api/common"
	"hboat/grpc/transfer/pool"
	"hboat/pkg/basic/mongo"
	"net/http"

	pb "hboat/grpc/transfer/proto"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Tc struct {
	Ports    []interface{} `yaml:"ports"`
	Action   string        `yaml:"action"`
	Level    string        `yaml:"level"`
	Name     string        `yaml:"name"`
	Ingress  bool          `yaml:"ingress"`
	Address  string        `yaml:"address"`
	Protocol string        `yaml:"protocol"`
}

type EguardConfig struct {
	Tc []Tc `yaml:"tc"`
}

// requests
type pluginConfigReq struct {
	AgentID string `form:"agent_id" binding:"required"`
	Name    string `form:"name" binding:"required"`
	Config  string `form:"config"`
}

func PluginConfig(c *gin.Context) {
	req := pluginConfigReq{}
	if err := c.Bind(&req); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	filter := bson.M{
		"agent_id": req.AgentID,
		"name":     req.Name,
	}
	switch c.Request.Method {
	case http.MethodGet:
		var result map[string]interface{}
		err := mongo.MongoProxyImpl.ConfigC.FindOne(context.Background(), filter).Decode(&result)
		if err != nil {
			common.Response(c, common.ErrorCode, err.Error())
			return
		}
		common.Response(c, common.SuccessCode, result)
		return
	case http.MethodPost:
		// Send command
		if err := pool.GlobalGRPCPool.SendCommand(req.AgentID, &pb.Command{
			Task: &pb.PluginTask{
				Name: req.Name,
				Data: req.Config,
			},
		}); err != nil {
			common.Response(c, common.ErrorCode, err.Error())
			return
		}
		var m map[string]interface{}
		err := json.Unmarshal([]byte(req.Config), &m)
		if err != nil {
			common.Response(c, common.ErrorCode, err.Error())
			return
		}
		_, err = mongo.MongoProxyImpl.ConfigC.UpdateOne(
			context.Background(),
			filter,
			bson.M{
				"$set": bson.M{
					"agent_id": req.AgentID,
					"name":     req.Name,
					"config":   m,
				},
			},
			options.Update().SetUpsert(true),
		)
		if err != nil {
			common.Response(c, common.ErrorCode, err.Error())
			return
		}
		common.Response(c, common.SuccessCode, nil)
		return
	}
}
