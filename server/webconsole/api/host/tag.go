package host

import (
	"context"
	"hboat/api/common"
	"hboat/pkg/basic/mongo"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// agentTagResp represents the response structure for agent tags
type agentTagResp struct {
	Tags []string `json:"tags"`
}

// agentTagReq represents the request structure for agent tags
type agentTagReq struct {
	Name    string `form:"name" binding:"required"`
	AgentID string `form:"agent_id" binding:"required"`
}

// TagAction handles operations related to agent tags
func TagAction(c *gin.Context) {
	var req agentTagReq

	// Bind request parameters
	if err := c.Bind(&req); err != nil {
		common.Response(c, common.ErrorCode, "invalid request: "+err.Error())
		return
	}

	filter := bson.M{"agent_id": req.AgentID}

	// Handle HTTP methods
	switch c.Request.Method {
	case http.MethodDelete:
		handleDelete(c, filter, req.Name)
	case http.MethodGet:
		handleGet(c, filter)
	case http.MethodPut:
		handlePut(c, filter, req.Name)
	default:
		c.AbortWithStatus(http.StatusMethodNotAllowed)
	}
}

// handleDelete removes a tag from the specified agent
func handleDelete(c *gin.Context, filter bson.M, tagName string) {
	if _, err := mongo.MongoProxyImpl.StatusC.UpdateOne(
		context.TODO(),
		filter,
		bson.M{"$pull": bson.M{"tags": tagName}},
	); err != nil {
		common.Response(c, common.ErrorCode, "delete error: "+err.Error())
		return
	}
	common.Response(c, common.SuccessCode, nil)
}

// handleGet retrieves the tags associated with the specified agent
func handleGet(c *gin.Context, filter bson.M) {
	var result map[string]interface{}
	if err := mongo.MongoProxyImpl.StatusC.FindOne(context.Background(), filter).Decode(&result); err != nil {
		common.Response(c, common.ErrorCode, "fetch error: "+err.Error())
		return
	}

	resp := agentTagResp{}
	if val, ok := result["tags"]; ok {
		resp.Tags = val.([]string)
	}
	common.Response(c, common.SuccessCode, resp)
}

// handlePut adds a new tag to the specified agent
func handlePut(c *gin.Context, filter bson.M, tagName string) {
	_, err := mongo.MongoProxyImpl.StatusC.UpdateOne(
		context.Background(),
		filter,
		bson.M{"$addToSet": bson.M{"tags": tagName}},
		options.Update().SetUpsert(true),
	)
	if err != nil {
		common.Response(c, common.ErrorCode, "add tag error: "+err.Error())
		return
	}
	common.Response(c, common.SuccessCode, nil)
}
