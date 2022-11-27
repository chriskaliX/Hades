// plugin operations
package plugin

import (
	"context"
	ds "hboat/datasource"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"hboat/server/api/common"
	"time"

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
}

func PluginInsert(c *gin.Context) {
	var pConfig PluginConfig
	if err := c.BindJSON(&pConfig); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	// result
	res := ds.PluginC.FindOne(
		context.Background(),
		bson.M{"name": pConfig.Name, "pversion": pConfig.Pversion},
	)
	if res.Err() == nil {
		common.Response(c, common.ErrorCode, "plugin already exists")
		return
	}
	now := time.Now().Unix()
	pConfig.CreateAt = now
	pConfig.ModifyAt = now
	if _, err := ds.PluginC.InsertOne(
		context.Background(),
		pConfig,
	); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}

	common.Response(c, common.SuccessCode, nil)
}

func PluginSelect(c *gin.Context) {
	name := c.GetString("name")
	pversion := c.GetString("pversion")
	res := ds.PluginC.FindOne(
		context.Background(),
		bson.M{"name": name, "pversion": pversion},
	)
	if res.Err() != nil {
		common.Response(c, common.ErrorCode, "plugin not exists")
		return
	}
	var plg PluginConfig
	if err := res.Decode(&plg); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	common.Response(c, common.SuccessCode, plg)
}

func PluginDel(c *gin.Context) {
	name := c.Query("name")
	pversion := c.Query("pversion")
	_, err := ds.PluginC.DeleteOne(
		context.Background(),
		bson.M{"name": name, "pversion": pversion},
	)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	common.Response(c, common.SuccessCode, nil)
}

func PluginUpdate(c *gin.Context) {
	var pConfig PluginConfig
	if err := c.BindJSON(&pConfig); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	pConfig.ModifyAt = time.Now().Unix()
	if _, err := ds.PluginC.UpdateOne(
		context.Background(),
		bson.M{"name": pConfig.Name, "pversion": pConfig.Pversion},
		bson.M{"$set": bson.M{"urls": pConfig.Urls, "sha256": pConfig.Sha256}},
	); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
	}

	common.Response(c, common.SuccessCode, nil)
}

type PluginListResp struct {
	// plugins and it's version
	List []PluginConfig `json:"plugins"`
}

func PluginList(c *gin.Context) {
	var plgResp PluginListResp
	plgResp.List = make([]PluginConfig, 0)
	cur, err := ds.PluginC.Find(
		context.Background(),
		bson.D{},
	)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	defer cur.Close(context.Background())
	for cur.Next(context.Background()) {
		var temp PluginConfig
		err = cur.Decode(&temp)
		if err != nil {
			continue
		}
		plgResp.List = append(plgResp.List, temp)
	}
	common.Response(c, common.SuccessCode, plgResp)
}

type PluginRequest struct {
	AgentID string `json:"agent_id"`
	Name    string `json:"name"`
	Version string `json:"pversion"`
}

// For now, only single instance is considered
func SendPlugin(c *gin.Context) {
	var pReq PluginRequest
	err := c.BindJSON(&pReq)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	var plgConfig PluginConfig
	err = ds.PluginC.FindOne(
		context.Background(),
		bson.M{"name": pReq.Name, "pversion": pReq.Version}).Decode(&plgConfig)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	command := pb.Command{}
	command.Config = []*pb.ConfigItem{
		{
			Name:        plgConfig.Name,
			Version:     plgConfig.Pversion,
			SHA256:      plgConfig.Sha256,
			DownloadURL: plgConfig.Urls,
		},
	}
	// Add the plugins with status on
	// for single grpc now
	// TODO: let the frontend controls this
	// BUG: logical problem, everytime a grpc reconnect, the plugin need to get from mongo
	// or just wait the plugin heartbeat
	// (or enforce the heartbeat of all in very first time)
	conn, err := pool.GlobalGRPCPool.Get(pReq.AgentID)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	for name, detail := range conn.PluginDetail {
		if name == plgConfig.Name {
			continue
		}
		version, ok := detail["pversion"]
		if !ok {
			continue
		}
		command.Config = append(command.Config, &pb.ConfigItem{
			Name:    name,
			Version: version.(string),
			SHA256:  plgConfig.Sha256,
		})
	}

	err = pool.GlobalGRPCPool.SendCommand(pReq.AgentID, &command)
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	common.Response(c, common.SuccessCode, nil)
}
