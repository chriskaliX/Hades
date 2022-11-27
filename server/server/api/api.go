package api

import (
	"fmt"
	gApi "hboat/server/api/grpc"
	"hboat/server/api/host"
	"hboat/server/api/plugin"

	"github.com/gin-contrib/cors"

	"github.com/gin-gonic/gin"
)

func RunGrpcServer(port int) {
	router := gin.Default()
	router.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"POST, GET, OPTIONS, PUT, DELETE,UPDATE"},
		AllowHeaders: []string{"*"},
	}))
	rGroup := router.Group("/api/v1/grpc/")
	// TODO: auth middleware
	rGroup.POST("/command", gApi.SendCommand)
	rGroup.GET("/conn/count", gApi.AgentCount)
	rGroup.GET("/conn/stat", gApi.AgentStat)
	rGroup.GET("/conn/basic", gApi.AgentBasic)

	gGroup := router.Group("/api/v1/plugin")
	gGroup.GET("/list", plugin.PluginList)
	gGroup.POST("/insert", plugin.PluginInsert)
	gGroup.POST("/update", plugin.PluginUpdate)
	gGroup.GET("/select", plugin.PluginSelect)
	gGroup.GET("/delete", plugin.PluginDel)
	gGroup.POST("/send", plugin.SendPlugin)

	aGroup := router.Group("/api/v1/asset")
	aGroup.GET("get", host.AgentAsset)

	router.Run(fmt.Sprintf(":%d", port))
}
