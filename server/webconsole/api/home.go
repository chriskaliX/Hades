package api

import (
	"context"
	"hboat/api/common"
	"hboat/pkg/basic/mongo"
	"hboat/pkg/basic/redis"
	"hboat/pkg/conf"
	"math"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type homePageResp struct {
	// assets
	HostOnline  int64 `json:"host_online"`
	HostOffline int64 `json:"host_offline"`
	Container   int64 `json:"container"`
	Service     int64 `json:"service"`
	// log record
	Record []record `json:"record"`
	// security alerts
	Alert    []int `json:"alert"` // 7 days alert count
	Vul      []int `json:"vul"`
	Critical int   `json:"critical"`
	High     int   `json:"high"`
	// DB delay
	RedisDelay int64 `json:"redis_delay"`
	MongoDelay int64 `json:"mongo_delay"`
}

type record struct {
	GmtCreate int64  `json:"gmt_create"`
	Message   string `json:"message"`
	Operator  string `json:"operator"`
}

func HomePage(c *gin.Context) {
	var resp homePageResp
	var err error
	resp.HostOnline, err = mongo.MongoProxyImpl.StatusC.CountDocuments(context.Background(), bson.M{"last_heartbeat_time": bson.M{"$gt": time.Now().Unix() - conf.Config.Backend.AgentHBOfflineSec}})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.HostOffline, err = mongo.MongoProxyImpl.StatusC.CountDocuments(context.Background(), bson.M{})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.HostOffline = resp.HostOffline - resp.HostOnline
	// 是否需要添加 Update time 过滤?
	resp.Container, err = mongo.MongoProxyImpl.AssetC.CountDocuments(context.Background(), bson.M{"data_type": 3018})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.Service, err = mongo.MongoProxyImpl.AssetC.CountDocuments(context.Background(), bson.M{"data_type": 3008})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	// records
	findOptions := options.Find()
	findOptions.SetLimit(5)
	findOptions.SetSort(bson.M{"gmt_create": -1})
	cur, err := mongo.MongoProxyImpl.RecordC.Find(context.Background(), bson.D{}, findOptions)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	defer cur.Close(context.Background())
	resp.Record = make([]record, 0)
	for cur.Next(context.Background()) {
		var result map[string]interface{}
		err := cur.Decode(&result)
		if err != nil {
			common.Response(c, common.ErrorCode, err.Error())
			return
		}
		// 处理查询结果
		resp.Record = append(resp.Record, record{
			GmtCreate: result["gmt_create"].(int64),
			Operator:  result["operator"].(string),
			Message:   result["message"].(string),
		})
	}
	// TODO: finished the alert
	resp.Alert = []int{0, 1, 5, 4, 2, 1}
	resp.Vul = []int{7, 2, 4, 1, 1, 3}
	resp.Critical = 2
	resp.High = 5
	// Ping the redis / mongodb
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	if _, err = redis.RedisProxyImpl.Client.Ping(ctx).Result(); err != nil {
		resp.RedisDelay = math.MaxInt64
	} else {
		elapsed := time.Since(start).Milliseconds()
		resp.RedisDelay = elapsed
	}
	start = time.Now()
	if err = mongo.MongoProxyImpl.StatusC.Database().Client().Ping(ctx, nil); err != nil {
		resp.MongoDelay = math.MaxInt64
	} else {
		elapsed := time.Since(start).Milliseconds()
		resp.MongoDelay = elapsed
	}

	common.Response(c, common.SuccessCode, resp)
}
