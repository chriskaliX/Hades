package grpc

import (
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"hboat/server/api/common"

	"github.com/gin-gonic/gin"
)

type CommandRequest struct {
	AgentID string     `json:"agent_id" bson:"agent_id" binding:"required"`
	Command pb.Command `json:"command" bson:"command" binding:"required"`
}

func SendCommand(c *gin.Context) {
	var command CommandRequest
	// BindJSON returns 400 status code if error occurs while
	// ShouldBindJSON returns 200, which should never happen.
	// In this case, no difference for two functions since
	// we only parse once
	err := c.BindJSON(&command)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	err = pool.GlobalGRPCPool.SendCommand(command.AgentID, &command.Command)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	common.Response(c, common.SuccessCode, nil)
}
