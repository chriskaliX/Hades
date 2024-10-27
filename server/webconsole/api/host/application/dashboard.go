package application

import (
	"context"
	"fmt"
	"hboat/api/common"
	"hboat/grpc/handler"
	"hboat/pkg/basic/mongo"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type dashboardResp struct {
	ContainerCount   int64 `json:"container_count"`
	ProcessCount     int64 `json:"process_count"`
	UserCount        int64 `json:"user_count"`
	SystemdCount     int64 `json:"systemd_count"`
	ApplicationCount int64 `json:"application_count"`
	CrontabCount     int64 `json:"crontab_count"`
	KmodCount        int64 `json:"kmod_count"`
	SocketCount      int64 `json:"socket_count"` // open port
	BpfCount         int64 `json:"bpf_count"`
	SocketTop        []top `json:"socket_top"`
	SystemdTop       []top `json:"systemd_top"`
	ApplicationTop   []top `json:"application_top"`
}

type top struct {
	Key   interface{} `json:"_id" bson:"_id"`
	Value int64       `json:"total" bson:"total"`
}

const countLimit int64 = 9999

// dashboard or we say overview
func Dashboard(c *gin.Context) {
	var resp dashboardResp

	containerCount, err := getCount(bson.M{"data_type": 3018})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.ContainerCount = containerCount
	processCount, err := getCount(bson.M{"data_type": 1001})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.ProcessCount = processCount
	userCount, err := getCount(bson.M{"data_type": 3004})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.UserCount = userCount
	systemdCount, err := getCount(bson.M{"data_type": 3011})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.SystemdCount = systemdCount
	applicationCount, err := getCount(bson.M{"data_type": 3008})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.ApplicationCount = applicationCount
	crontabCount, err := getCount(bson.M{"data_type": 2001})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.CrontabCount = crontabCount
	kmodCount, err := getCount(bson.M{"data_type": 3009})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.KmodCount = kmodCount
	socketCount, err := getCount(bson.M{"data_type": 5001, "sip": "0.0.0.0"})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.SocketCount = socketCount
	bpfCount, err := getCount(bson.M{"data_type": 3014})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.BpfCount = bpfCount

	// top5
	// socket
	resp.SocketTop = make([]top, 0)
	socketPipeline := bson.A{
		bson.M{"$match": bson.M{
			"$and": []bson.M{
				{"data_type": 5001},
				{"sip": "0.0.0.0"},
				{"update_time": bson.M{"$gt": time.Now().Unix() - 24*60*60}},
			},
		}},
		bson.D{primitive.E{Key: "$group", Value: bson.D{
			primitive.E{Key: "_id", Value: "$sport"},
			primitive.E{Key: "total", Value: bson.D{primitive.E{Key: "$sum", Value: 1}}},
		}}},
		bson.D{primitive.E{Key: "$sort", Value: bson.D{primitive.E{Key: "total", Value: -1}}}},
		bson.D{primitive.E{Key: "$limit", Value: 5}},
	}
	ctx := context.Background()
	cur, err := mongo.MongoProxyImpl.AssetC.Aggregate(ctx, socketPipeline)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		var temp top
		cur.Decode(&temp)
		resp.SocketTop = append(resp.SocketTop, temp)
	}
	// systemd
	resp.SystemdTop = make([]top, 0)
	systemdPipeline := bson.A{
		bson.M{"$match": bson.M{
			"$and": []bson.M{
				{"data_type": 3011},
				{"update_time": bson.M{"$gt": time.Now().Unix() - 24*60*60}},
			},
		}},
		bson.D{primitive.E{Key: "$group", Value: bson.D{
			primitive.E{Key: "_id", Value: "$name"},
			primitive.E{Key: "total", Value: bson.D{primitive.E{Key: "$sum", Value: 1}}},
		}}},
		bson.D{primitive.E{Key: "$sort", Value: bson.D{primitive.E{Key: "total", Value: -1}}}},
		bson.D{primitive.E{Key: "$limit", Value: 5}},
	}
	cur, err = mongo.MongoProxyImpl.AssetC.Aggregate(ctx, systemdPipeline)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		var temp top
		cur.Decode(&temp)
		resp.SystemdTop = append(resp.SystemdTop, temp)
	}
	// application
	resp.ApplicationTop = make([]top, 0)
	appPipeline := bson.A{
		bson.M{"$match": bson.M{
			"$and": []bson.M{
				{"data_type": 3008},
				{"update_time": bson.M{"$gt": time.Now().Unix() - 24*60*60}},
			},
		}},
		bson.D{primitive.E{Key: "$group", Value: bson.D{
			primitive.E{Key: "_id", Value: "$name"},
			primitive.E{Key: "total", Value: bson.D{primitive.E{Key: "$sum", Value: 1}}},
		}}},
		bson.D{primitive.E{Key: "$sort", Value: bson.D{primitive.E{Key: "total", Value: -1}}}},
		bson.D{primitive.E{Key: "$limit", Value: 5}},
	}
	cur, err = mongo.MongoProxyImpl.AssetC.Aggregate(ctx, appPipeline)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		temp := top{}
		cur.Decode(&temp)
		resp.ApplicationTop = append(resp.ApplicationTop, temp)
	}
	resp.ApplicationTop = fillTop(resp.ApplicationTop)
	resp.SystemdTop = fillTop(resp.SystemdTop)
	resp.SocketTop = fillTop(resp.SocketTop)

	common.Response(c, common.SuccessCode, &resp)
}

// general assets search
func GeneralApp(c *gin.Context) {
	type request struct {
		Type string `form:"type" binding:"required"`
	}

	type response struct {
		Total  int32                    `json:"total"`
		Assets []map[string]interface{} `json:"assets"`
	}

	pageReq := common.PageReq{}
	if err := c.Bind(&pageReq); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	// agent asset request binding
	req := request{}
	if err := c.Bind(&req); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	dt, ok := handler.EventNameCache[req.Type]
	if !ok {
		common.Response(c, common.ErrorCode, fmt.Sprintf("type %s is not registed", req.Type))
		return
	}

	respCommon, err := common.DBPageSearch(context.TODO(), mongo.MongoProxyImpl.AssetC, &pageReq, bson.M{"data_type": dt.ID(), "update_time": bson.M{"$gt": time.Now().Unix() - 3*24*60*60}})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
	}

	resp := response{
		Total:  int32(respCommon.Total),
		Assets: respCommon.Items,
	}
	common.Response(c, common.SuccessCode, resp)
}

func getCount(filter bson.M) (int64, error) {
	filter["update_time"] = bson.M{"$gt": time.Now().Unix() - 60*60*24*3}
	var max int64 = countLimit
	opts := &options.CountOptions{
		Limit: &max,
	}
	return mongo.MongoProxyImpl.AssetC.CountDocuments(context.Background(), filter, opts)
}

func fillTop(t []top) []top {
	if len(t) < 5 {
		t = append(t, make([]top, 5-len(t))...)
	}
	return t
}
