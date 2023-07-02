package application

import (
	"context"
	"hboat/api/common"
	"hboat/pkg/basic/mongo"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func ContainerDash(c *gin.Context) {
	type response struct {
		Online  int64 `json:"online"`
		Offline int64 `json:"offline"`
	}

	var resp response
	var err error

	resp.Online, err = getCount(bson.M{"data_type": 3018, "state": "running"})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	resp.Offline, err = getCount(bson.M{"data_type": 3018, "state": "exited"})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	common.Response(c, common.SuccessCode, &resp)
}

func ContainerTop(c *gin.Context) {
	type request struct {
		State string `json:"state"`
	}
	type response struct {
		Top []top `json:"top"`
	}

	var req request
	var resp = response{
		Top: make([]top, 0),
	}

	if err := c.Bind(&req); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	var match bson.M
	if req.State == "" {
		match = bson.M{"$match": bson.M{
			"$and": []bson.M{
				bson.M{"data_type": 3018},
				bson.M{"update_time": bson.M{"$gt": time.Now().Unix() - 24*60*60}},
			},
		}}
	} else {
		match = bson.M{"$match": bson.M{
			"$and": []bson.M{
				bson.M{"data_type": 3018},
				bson.M{"state": req.State},
				bson.M{"update_time": bson.M{"$gt": time.Now().Unix() - 24*60*60}},
			},
		}}
	}

	pipeline := bson.A{match,
		bson.D{primitive.E{Key: "$group", Value: bson.D{
			primitive.E{Key: "_id", Value: "$image_name_without_version"},
			primitive.E{Key: "total", Value: bson.D{primitive.E{Key: "$sum", Value: 1}}},
		}}},
		bson.D{primitive.E{Key: "$sort", Value: bson.D{primitive.E{Key: "total", Value: -1}}}},
		bson.D{primitive.E{Key: "$limit", Value: 3}},
	}
	ctx := context.Background()
	cur, err := mongo.MongoProxyImpl.AssetC.Aggregate(ctx, pipeline)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		var temp top
		cur.Decode(&temp)
		resp.Top = append(resp.Top, temp)
	}

	common.Response(c, common.SuccessCode, resp)
}
