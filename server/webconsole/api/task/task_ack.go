package task

import (
	"context"
	"hboat/api/common"
	"hboat/pkg/basic/mongo"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// GetTaskAck queries the completion status of an on-demand collection task.
// GET /api/v1/task/ack?token=<token>
//
// Response data:
//
//	{ "token": "...", "agent_id": "...", "status": "pending|success|failed", "msg": "...", "timestamp": 0 }
func GetTaskAck(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		common.Response(c, common.ErrorCode, "token is required")
		return
	}

	var doc bson.M
	if err := mongo.MongoProxyImpl.TaskAckC.FindOne(
		context.Background(),
		bson.M{"token": token},
	).Decode(&doc); err != nil {
		// Not found yet — treat as still pending
		common.Response(c, common.SuccessCode, bson.M{"token": token, "status": "pending"})
		return
	}

	common.Response(c, common.SuccessCode, doc)
}

// ListTaskAck returns recent tasks for a given agent_id.
// GET /api/v1/task/list?agent_id=<id>&size=<n>
func ListTaskAck(c *gin.Context) {
	agentID := c.Query("agent_id")
	if agentID == "" {
		common.Response(c, common.ErrorCode, "agent_id is required")
		return
	}
	size := int64(50)
	cursor, err := mongo.MongoProxyImpl.TaskAckC.Find(
		context.Background(),
		bson.M{"agent_id": agentID},
		options.Find().SetSort(bson.D{{Key: "create_at", Value: -1}}).SetLimit(size),
	)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	defer cursor.Close(context.Background())
	var items []bson.M
	if err := cursor.All(context.Background(), &items); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	if items == nil {
		items = []bson.M{}
	}
	common.Response(c, common.SuccessCode, items)
}
