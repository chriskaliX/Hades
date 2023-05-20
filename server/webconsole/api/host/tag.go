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

// Agent tags operations
type agentTagResp struct {
	Tags []string `json:"tags"`
}

type agentTagReq struct {
	Name    string `form:"name" binding:"required"`
	AgentID string `form:"agent_id" binding:"required"`
}

func TagAction(c *gin.Context) {
	var err error
	req := agentTagReq{}
	if err = c.Bind(&req); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	filter := bson.M{"agent_id": req.AgentID}
	switch c.Request.Method {
	case http.MethodDelete:
		if _, err = mongo.MongoProxyImpl.StatusC.UpdateOne(
			context.TODO(),
			filter,
			bson.M{"$pull": bson.M{"tags": req.Name}},
		); err != nil {
			common.Response(c, common.ErrorCode, err.Error())
			return
		}
	case http.MethodGet:
		var result map[string]interface{}
		err := mongo.MongoProxyImpl.StatusC.FindOne(context.Background(), filter).Decode(&result)
		if err != nil {
			common.Response(c, common.ErrorCode, err.Error())
			return
		}
		var resp = agentTagResp{}
		if val, ok := result["tags"]; ok {
			resp.Tags = val.([]string)
		}
		common.Response(c, common.SuccessCode, resp)
	case http.MethodPut:
		_, err := mongo.MongoProxyImpl.StatusC.UpdateOne(
			context.Background(),
			filter,
			bson.M{"$addToSet": bson.M{"tags": req.Name}},
			options.Update().SetUpsert(true),
		)
		if err != nil {
			common.Response(c, common.ErrorCode, err.Error())
			return
		}
		common.Response(c, common.SuccessCode, nil)
		return
	}
}
