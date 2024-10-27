// asset get the asset information of agent
package host

import (
	"context"
	"fmt"
	"hboat/api/common"
	"hboat/grpc/handler"
	"hboat/pkg/basic/mongo"
	"time"

	"golang.org/x/exp/slices"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

// agentAssetResp represents the response structure for agent assets
type agentAssetResp struct {
	Total  int32                    `json:"total"`
	Assets []map[string]interface{} `json:"assets"`
}

// agentAssetReq represents the request structure for agent assets
type agentAssetReq struct {
	Type    string `form:"type" binding:"required"`
	AgentID string `form:"agent_id" binding:"required"`
}

// AgentAsset handles requests for agent asset information
func AgentAsset(c *gin.Context) {
	pageReq := common.PageReq{}
	assetReq := agentAssetReq{}

	// Bind request parameters and handle errors
	if err := bindRequests(c, &pageReq, &assetReq); err != nil {
		return
	}

	// Validate asset type
	if err := validateAssetType(assetReq.Type); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	// Fetch asset information based on type
	var resp agentAssetResp
	var err error
	if assetReq.Type == "plugins" {
		resp, err = handlePlugins(assetReq.AgentID)
	} else {
		resp, err = handleCommonAssets(assetReq, pageReq)
	}

	// Handle potential error from fetching asset information
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	common.Response(c, common.SuccessCode, resp)
}

// bindRequests binds the request parameters for pagination and asset request
func bindRequests(c *gin.Context, pageReq *common.PageReq, assetReq *agentAssetReq) error {
	if err := c.Bind(pageReq); err != nil {
		common.Response(c, common.ErrorCode, "invalid page request: "+err.Error())
		return err
	}
	if err := c.Bind(assetReq); err != nil {
		common.Response(c, common.ErrorCode, "invalid asset request: "+err.Error())
		return err
	}
	return nil
}

// validateAssetType checks if the provided asset type is allowed
func validateAssetType(assetType string) error {
	if !slices.Contains(common.AssetAllowList, assetType) {
		return fmt.Errorf("type %s is not supported", assetType)
	}
	if _, ok := handler.EventNameCache[assetType]; !ok {
		return fmt.Errorf("type %s is not registered", assetType)
	}
	return nil
}

// handlePlugins fetches and processes plugin information for the specified agent
func handlePlugins(agentID string) (agentAssetResp, error) {
	var resp agentAssetResp
	var as mongo.AgentStatus

	if err := mongo.MongoProxyImpl.StatusC.FindOne(context.Background(), bson.M{"agent_id": agentID}).Decode(&as); err != nil {
		return resp, err
	}

	pluginList := make([]map[string]interface{}, 0, len(as.PluginDetail))
	for _, detail := range as.PluginDetail {
		detail["status"] = false // Default status
		if hb, ok := detail["last_heartbeat_time"].(int64); ok && time.Now().Unix()-hb <= 3*60 {
			detail["status"] = true // Update status if within heartbeat time
		}
		pluginList = append(pluginList, detail)
	}

	resp = agentAssetResp{
		Total:  int32(len(pluginList)),
		Assets: pluginList,
	}
	return resp, nil
}

// handleCommonAssets fetches and processes common asset information for the specified agent
func handleCommonAssets(assetReq agentAssetReq, pageReq common.PageReq) (agentAssetResp, error) {
	respCommon, err := common.DBPageSearch(context.TODO(), mongo.MongoProxyImpl.AssetC, &pageReq, bson.M{"agent_id": assetReq.AgentID, "data_type": handler.EventNameCache[assetReq.Type].ID()})
	if err != nil {
		return agentAssetResp{}, err
	}
	return agentAssetResp{
		Total:  int32(respCommon.Total),
		Assets: respCommon.Items,
	}, nil
}
