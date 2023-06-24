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
	// security alerts
	Record   []record                 `json:"record"`
	Alert    []map[string]interface{} `json:"alert"` // 7 days alert count
	Vul      []int                    `json:"vul"`
	Critical int                      `json:"critical"`
	High     int                      `json:"high"`
	// DB delay
	RedisDelay int64 `json:"redis_delay"`
	MongoDelay int64 `json:"mongo_delay"`
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
	// record
	findOptions := options.Find()
	findOptions.SetLimit(6)
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
		resp.Record = append(resp.Record, record{
			GmtCreate: result["gmt_create"].(int64),
			Operator:  result["operator"].(string),
			Message:   result["message"].(string),
		})
	}

	// TODO: finished the alert
	resp.Alert = []map[string]interface{}{
		{"time": "2022-01-01", "value": 1},
		{"time": "2022-01-02", "value": 2},
		{"time": "2022-01-03", "value": 7},
	}
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

type recordResp struct {
	Record []record `json:"record"`
}

type record struct {
	GmtCreate int64  `json:"gmt_create"`
	Message   string `json:"message"`
	Operator  string `json:"operator"`
}

// Operation records
func Record(c *gin.Context) {
	var resp recordResp
	findOptions := options.Find()
	findOptions.SetLimit(6)
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
		resp.Record = append(resp.Record, record{
			GmtCreate: result["gmt_create"].(int64),
			Operator:  result["operator"].(string),
			Message:   result["message"].(string),
		})
	}
	common.Response(c, common.SuccessCode, resp)
}
