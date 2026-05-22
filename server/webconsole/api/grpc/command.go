package grpc

import (
	"context"
	"fmt"
	"hboat/api/common"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"hboat/pkg/basic/mongo"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/xid"
	"go.mongodb.org/mongo-driver/bson"
)

type CommandRequest struct {
	AgentID string     `json:"agent_id" bson:"agent_id" binding:"required"`
	Command pb.Command `json:"command" bson:"command" binding:"required"`
}

func SendCommand(c *gin.Context) {
	var command CommandRequest
	err := c.BindJSON(&command)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	// When the command carries a Task, generate a token and track it.
	var token string
	if command.Command.Task != nil {
		token = fmt.Sprintf("task-%s", xid.New())
		command.Command.Task.Token = token
		// Pre-insert a "pending" record so the frontend can poll immediately.
		doc := bson.M{
			"token":     token,
			"agent_id":  command.AgentID,
			"status":    "pending",
			"msg":       "",
			"data_type": command.Command.Task.DataType,
			"create_at": time.Now().Unix(),
			"user":      c.GetString("username"),
		}
		mongo.MongoProxyImpl.TaskAckC.InsertOne(context.Background(), doc) //nolint:errcheck
	}

	err = pool.GlobalGRPCPool.SendCommand(command.AgentID, &command.Command)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	common.Response(c, common.SuccessCode, bson.M{"token": token})
}
