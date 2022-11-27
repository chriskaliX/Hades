// asset get the asset information of agent
package host

import (
	"context"
	"fmt"
	ds "hboat/datasource"
	"hboat/server/api/common"

	"golang.org/x/exp/slices"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

var typeAllowList = []string{"users", "sockets", "processes", "crons"}

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
	if !slices.Contains(typeAllowList, assetReq.Type) {
		common.Response(c, common.ErrorCode, fmt.Sprintf("type %s is not supported", assetReq.Type))
		return
	}
	// pipeline
	pipeline := bson.A{
		bson.M{"$match": bson.M{"agent_id": assetReq.AgentID}},
	}
	// get count
	countPipeline := append(pipeline, bson.M{
		"$project": bson.D{
			{Key: "count", Value: bson.M{"$size": "$" + assetReq.Type}},
			{Key: "_id", Value: 0}}})
	if countCur, err := ds.AssetC.Aggregate(
		context.TODO(),
		countPipeline,
	); err == nil {
		defer countCur.Close(context.Background())
		var count []map[string]interface{}
		if err = countCur.All(context.Background(), &count); err != nil {
			common.Response(c, common.ErrorCode, err)
			return
		}
		if len(count) > 0 {
			resp.Total = count[0]["count"].(int32)
		}
	}

	pipeline = append(pipeline, bson.M{"$project": bson.D{
		{Key: assetReq.Type, Value: 1}, {Key: "_id", Value: 0},
	}}, bson.M{"$unwind": "$" + assetReq.Type})

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
	cur, err := ds.AssetC.Aggregate(
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
		resp.Assets = append(resp.Assets, v[assetReq.Type])
	}

	common.Response(c, common.SuccessCode, resp)
}
