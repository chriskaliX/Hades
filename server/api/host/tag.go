package host

import (
	"fmt"
	"hboat/api/common"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Agent tags operations
type agentTagResp struct {
	Tags []string `json:"tags"`
}

type agentTagReq struct {
	Name    string `form:"name" binding:"required"`
	AgentID string `form:"agent_id" binding:"required"`
}

func AgentTag(c *gin.Context) {
	req := agentTagReq{}
	if err := c.Bind(&req); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	switch c.Request.Method {
	case http.MethodGet:
		// set tags by name

	case http.MethodDelete:
	default:
		common.Response(c, common.ErrorCode, fmt.Sprintf("method %s not support", c.Request.Method))
		return
	}
}

// Tags operations
