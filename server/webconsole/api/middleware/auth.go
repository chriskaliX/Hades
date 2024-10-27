package middleware

import (
	"context"
	"hboat/pkg/basic/redis"
	"hboat/pkg/conf"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/exp/slices"
)

// Predefined errors and constants
const (
	nilErrRedis   = "redis: nil"
	unauthorized  = http.StatusUnauthorized
	internalError = http.StatusInternalServerError
)

// Whitelisted routes for unauthenticated access
var whitelist = []string{
	"/api/v1/user/login",
}

// Auth middleware to protect routes
func Auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Bypass authentication if disabled
		if !conf.Config.Backend.Auth {
			c.Next()
			return
		}

		// Allow access to whitelisted routes
		if slices.Contains(whitelist, c.Request.URL.Path) {
			c.Next()
			return
		}

		// Check for the authorization token
		token := c.GetHeader("token")
		if token == "" {
			c.AbortWithStatus(unauthorized)
			return
		}

		// Retrieve username from Redis
		username, err := getUsernameFromToken(token)
		if err != nil {
			c.AbortWithStatus(internalError)
			return
		}

		if username == "" {
			c.AbortWithStatus(unauthorized)
			return
		}

		c.Set("username", username)
		c.Next()
	}
}

// getUsernameFromToken retrieves the username associated with the given token from Redis
func getUsernameFromToken(token string) (string, error) {
	result := redis.RedisProxyImpl.Client.Get(context.Background(), token)
	if result.Err() != nil {
		return "", result.Err() // Return any error directly
	}
	return result.Val(), nil // Return the retrieved username
}
