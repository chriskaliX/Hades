package monitor

import (
	"hboat/api/common"
	"hboat/pkg/basic/mongo"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

func MetricPerformance(c *gin.Context) {
	startTime := c.Query("start")
	endTime := c.Query("end")
	agentID := c.Query("agent_id")

	// 解析开始时间
	start, err := time.Parse(time.RFC3339, startTime)
	if err != nil {
		common.Response(c, common.ErrorCode, "Invalid start time")
		return
	}

	// 解析结束时间
	end, err := time.Parse(time.RFC3339, endTime)
	if err != nil {
		common.Response(c, common.ErrorCode, "Invalid end time")
		return
	}

	// 设置查询过滤条件
	filter := bson.M{
		"timestamp": bson.M{
			"$gte": start,
			"$lte": end,
		},
		"agent_id": agentID,
	}

	// 从 MongoDB 获取数据
	cur, err := mongo.MongoProxyImpl.MetricC.Find(c, filter)
	if err != nil {
		common.Response(c, common.ErrorCode, "Error fetching metrics")
		return
	}
	defer cur.Close(c)

	var metricsList []bson.M
	for cur.Next(c) {
		var metric bson.M
		if err := cur.Decode(&metric); err != nil {
			common.Response(c, common.ErrorCode, "Error decoding metrics")
			return
		}
		metricsList = append(metricsList, metric)
	}

	if err := cur.Err(); err != nil {
		common.Response(c, common.ErrorCode, "Cursor error")
		return
	}

	common.Response(c, common.SuccessCode, metricsList)
}