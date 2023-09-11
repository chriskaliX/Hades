package host

type metricReq struct {
	AgentID string `form:"agent_id" binding:"required"`
}

// func Metrics(c *gin.Context) {
// 	req := metricReq{}
// 	if err := c.Bind(&req); err != nil {
// 		common.Response(c, common.ErrorCode, err.Error())
// 		return
// 	}
// 	mongo.MongoProxyImpl.MetricC.Find(context.TODO(), bson.M{
// 		"agent_id": req.AgentID,
// 		"timestamp": bson.M{
// 			"$gte":
// 		},
// 	})
// }
