// asset get the asset information of agent
package host

import (
	"context"
	"fmt"
	"hboat/api/common"
	"hboat/grpc/handler"
	"hboat/pkg/basic/mongo"

	"golang.org/x/exp/slices"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

var typeAllowlist = []string{
	"users", "sockets", "processes", "crons", "apps", "kmods", "iptables", "net_interfaces", "containers",
}

type AgentAssetResp struct {
	Total  int32         `json:"total"`
	Assets []interface{} `json:"assets"`
}

type agentAssetReq struct {
	Type    string `form:"type" binding:"required"`
	AgentID string `form:"agent_id" binding:"required"`
}

func AgentAsset(c *gin.Context) {
	resp := AgentAssetResp{}
	// page request binding
	pageReq := common.PageReq{}
	if err := c.Bind(&pageReq); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	// agent asset request binding
	assetReq := agentAssetReq{}
	if err := c.Bind(&assetReq); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	// type check
	if !slices.Contains(typeAllowlist, assetReq.Type) {
		common.Response(c, common.ErrorCode, fmt.Sprintf("type %s is not supported", assetReq.Type))
		return
	}
	dt, ok := handler.EventNameCache[assetReq.Type]
	if !ok {
		common.Response(c, common.ErrorCode, fmt.Sprintf("type %s is not registed", assetReq.Type))
		return
	}
	if count, err := mongo.AssetC.CountDocuments(context.TODO(), bson.M{"agent_id": assetReq.AgentID, "data_type": dt.ID()}); err == nil {
		resp.Total = int32(count)
	}

	// pipeline
	pipeline := bson.A{
		bson.M{"$match": bson.M{"agent_id": assetReq.AgentID, "data_type": dt.ID()}},
	}
	pipeline = append(pipeline, bson.M{"$project": bson.D{
		{Key: "_id", Value: 0}, {Key: "package_seq", Value: 0},
	}})

	if pageReq.OrderKey != "" {
		pipeline = append(pipeline, bson.M{
			"$sort": bson.D{
				{
					Key:   assetReq.Type + "." + pageReq.OrderKey,
					Value: pageReq.OrderValue,
				},
			},
		})
	}

	pipeline = append(pipeline, bson.D{{Key: "$skip",
		Value: (pageReq.Page - 1) * pageReq.Size}},
		bson.D{{Key: "$limit", Value: pageReq.Size}})
	// get result
	cur, err := mongo.AssetC.Aggregate(
		context.TODO(),
		pipeline,
	)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	defer cur.Close(context.Background())
	// parse into []interface{}
	raw := make([]map[string]interface{}, 0)
	if err = cur.All(context.TODO(), &raw); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	if len(raw) == 0 {
		return
	}

	for _, v := range raw {
		resp.Assets = append(resp.Assets, v)
	}

	common.Response(c, common.SuccessCode, resp)
}
