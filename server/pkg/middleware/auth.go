package middleware

import (
	"context"
	"hboat/pkg/basic/redis"
	"hboat/pkg/conf"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// auth 开关
		if !conf.Config.Backend.Auth {
			c.Next()
			return
		}
		// TODO: whitelist should be added

		// start check
		token := c.GetHeader("token")
		if token == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		s := redis.Inst.Get(context.Background(), token)
		if s.Err() != nil {
			zap.S().Error(s.Err())
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		username := s.Val()
		if username == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("username", username)
		c.Next()
	}
}
