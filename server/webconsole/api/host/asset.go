// asset get the asset information of agent
package host

import (
	"fmt"
	"hboat/api/common"
	"hboat/grpc/handler"
	"hboat/pkg/basic/mongo"

	"golang.org/x/exp/slices"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

var typeAllowlist = []string{
	"users", "sockets", "processes", "crons", "apps", "kmods", "iptables", "net_interfaces", "containers",
}

type AgentAssetResp struct {
	Total  int32                    `json:"total"`
	Assets []map[string]interface{} `json:"assets"`
}

type agentAssetReq struct {
	Type    string `form:"type" binding:"required"`
	AgentID string `form:"agent_id" binding:"required"`
}

func AgentAsset(c *gin.Context) {
	// page request binding
	pageReq := common.PageReq{}
	if err := c.Bind(&pageReq); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	// agent asset request binding
	assetReq := agentAssetReq{}
	if err := c.Bind(&assetReq); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	// type check
	if !slices.Contains(typeAllowlist, assetReq.Type) {
		common.Response(c, common.ErrorCode, fmt.Sprintf("type %s is not supported", assetReq.Type))
		return
	}
	dt, ok := handler.EventNameCache[assetReq.Type]
	if !ok {
		common.Response(c, common.ErrorCode, fmt.Sprintf("type %s is not registed", assetReq.Type))
		return
	}

	respCommon, err := common.DBPageSearch(mongo.MongoProxyImpl.AssetC, &pageReq, bson.M{"agent_id": assetReq.AgentID, "data_type": dt.ID()})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
	}
	resp := AgentAssetResp{
		Total:  int32(respCommon.Total),
		Assets: respCommon.Items,
	}
	common.Response(c, common.SuccessCode, resp)
}
