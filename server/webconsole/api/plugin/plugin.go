package plugin

import (
	"context"
	"fmt"
	"hboat/api/common"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"hboat/pkg/basic/mongo"
	"net/url"
	"time"

	"github.com/chriskaliX/SDK/config"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

type PluginConfig struct {
	Sha256   string   `json:"sha256" bson:"sha256" binding:"required"`
	Name     string   `json:"name" bson:"name" binding:"required"`
	Urls     []string `json:"urls" bson:"urls" binding:"required"`
	Pversion string   `json:"pversion" bson:"pversion" binding:"required"`
	CreateAt int64    `json:"create_at" bson:"create_at"`
	ModifyAt int64    `json:"modify_at" bson:"modify_at"`
	Desc     string   `json:"desc" bson:"desc"`
}

func PluginInsert(c *gin.Context) {
	var plugin PluginConfig
	if err := c.BindJSON(&plugin); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	// Check if the plugin already exists
	if err := mongo.MongoProxyImpl.PluginC.FindOne(context.Background(),
		bson.M{"name": plugin.Name, "pversion": plugin.Pversion}).Err(); err == nil {
		common.Response(c, common.ErrorCode, "plugin already exists")
		return
	}

	now := time.Now().Unix()
	plugin.CreateAt = now
	plugin.ModifyAt = now

	// Validate URLs
	if len(plugin.Urls) == 0 {
		common.Response(c, common.ErrorCode, "at least one URL is required")
		return
	}

	for _, u := range plugin.Urls {
		uri, err := url.Parse(u)
		if err != nil || (uri.Scheme != "http" && uri.Scheme != "https") {
			common.Response(c, common.ErrorCode, fmt.Sprintf("invalid URL: %s", u))
			return
		}
	}

	// Insert the plugin into the database
	if _, err := mongo.MongoProxyImpl.PluginC.InsertOne(context.Background(), plugin); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	common.LogRecord(c, fmt.Sprintf("plugin: %s, version: %s has been added", plugin.Name, plugin.Pversion))
	common.Response(c, common.SuccessCode, nil)
}

func PluginSelect(c *gin.Context) {
	name := c.GetString("name")
	pversion := c.GetString("pversion")

	var plugin PluginConfig
	if err := mongo.MongoProxyImpl.PluginC.FindOne(context.Background(), bson.M{"name": name, "pversion": pversion}).Decode(&plugin); err != nil {
		common.Response(c, common.ErrorCode, "plugin does not exist")
		return
	}
	common.Response(c, common.SuccessCode, plugin)
}

func PluginDel(c *gin.Context) {
	name := c.Query("name")
	pversion := c.Query("pversion")

	if _, err := mongo.MongoProxyImpl.PluginC.DeleteOne(context.Background(), bson.M{"name": name, "pversion": pversion}); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	common.LogRecord(c, fmt.Sprintf("plugin: %s, version: %s has been deleted", name, pversion))
	common.Response(c, common.SuccessCode, nil)
}

func PluginUpdate(c *gin.Context) {
	var plugin PluginConfig
	if err := c.BindJSON(&plugin); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	plugin.ModifyAt = time.Now().Unix()
	if _, err := mongo.MongoProxyImpl.PluginC.UpdateOne(context.Background(),
		bson.M{"name": plugin.Name, "pversion": plugin.Pversion},
		bson.M{"$set": bson.M{"urls": plugin.Urls, "sha256": plugin.Sha256}}); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	common.LogRecord(c, fmt.Sprintf("plugin: %s, version: %s has been updated", plugin.Name, plugin.Pversion))
	common.Response(c, common.SuccessCode, nil)
}

func PluginList(c *gin.Context) {
	var pageReq common.PageReq

	if err := c.ShouldBind(&pageReq); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	respCommon, err := common.DBPageSearch(context.TODO(), mongo.MongoProxyImpl.PluginC, &pageReq, bson.M{})
	if err != nil {
		return
	}

	response := common.PageResp{
		Total: respCommon.Total,
		Items: respCommon.Items,
	}

	common.Response(c, common.SuccessCode, response)
}

type PluginRequest struct {
	AgentID string `json:"agent_id"`
	Name    string `json:"name"`
	Version string `json:"pversion"`
	Action  string `json:"action"`
}

func SendPlugin(c *gin.Context) {
	var request PluginRequest
	if err := c.BindJSON(&request); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	switch request.Action {
	case "insert":
		actionInsert(c, request)
	case "delete":
		actionDelete(c, request)
	default:
		common.Response(c, common.ErrorCode, "unknown action")
	}
}

func actionInsert(c *gin.Context, request PluginRequest) {
	var pluginConfig PluginConfig
	if err := mongo.MongoProxyImpl.PluginC.FindOne(context.Background(), bson.M{"name": request.Name, "pversion": request.Version}).Decode(&pluginConfig); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	command := pb.Command{
		Config: []*pb.ConfigItem{
			{
				Name:        pluginConfig.Name,
				Version:     pluginConfig.Pversion,
				SHA256:      pluginConfig.Sha256,
				DownloadURL: pluginConfig.Urls,
			},
		},
	}

	// Gather existing plugins
	conn, err := pool.GlobalGRPCPool.Get(request.AgentID)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	for name, detail := range conn.GetPluginsList() {
		if name == pluginConfig.Name {
			continue
		}
		if version, ok := detail["pversion"]; ok {
			command.Config = append(command.Config, &pb.ConfigItem{
				Name:    name,
				Version: version.(string),
				SHA256:  pluginConfig.Sha256,
			})
		}
	}

	if err := pool.GlobalGRPCPool.SendCommand(request.AgentID, &command); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	common.Response(c, common.SuccessCode, nil)
}

func actionDelete(c *gin.Context, request PluginRequest) {
	if err := pool.GlobalGRPCPool.SendCommand(request.AgentID, &pb.Command{
		Task: &pb.PluginTask{
			DataType: config.TaskShutdown,
			Name:     request.Name,
		},
	}); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	common.Response(c, common.SuccessCode, nil)
}
