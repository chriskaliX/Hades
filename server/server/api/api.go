package api

import (
	"fmt"
	gApi "hboat/server/api/grpc"
	"hboat/server/api/host"
	"hboat/server/api/plugin"
	"net/http"

	"github.com/gin-contrib/cors"

	"github.com/gin-gonic/gin"
)

func CorsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "*")
		c.Header("Access-Control-Allow-Methods", "POST, GET, PUT, PATCH, OPTIONS")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Expose-Headers", "*")
		if c.Request.Method == "OPTIONS" {
			c.JSON(http.StatusOK, "")
			c.Abort()
			return
		}
		c.Next()
	}
}

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

	router.Use(CorsHandler())
	router.Run(fmt.Sprintf(":%d", port))
}
