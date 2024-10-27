package user

import (
	"context"
	"fmt"
	"hboat/api/common"
	"hboat/pkg/basic/mongo"
	"hboat/pkg/basic/redis"
	"hboat/pkg/basic/utils"
	"hboat/pkg/conf"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

// LoginRequest represents the login request structure
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Login handles user login
func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.BindJSON(&req); err != nil {
		common.Response(c, common.ErrorCode, "invalid request: "+err.Error())
		return
	}

	// Validate username and password
	if err := mongo.CheckPassword(req.Username, req.Password); err != nil {
		common.Response(c, common.ErrorCode, "authentication failed: "+err.Error())
		return
	}

	// Create session and store in Redis
	sessionID := utils.GenerateSession()
	duration := time.Duration(conf.Config.Backend.UserSessionLifetimeMin) * time.Minute
	if err := redis.RedisProxyImpl.Client.Set(context.Background(), sessionID, req.Username, duration).Err(); err != nil {
		common.Response(c, common.ErrorCode, "session error: "+err.Error())
		return
	}

	common.LogRecord(c, fmt.Sprintf("user %s logged in successfully", req.Username))
	// Respond with the token
	common.Response(c, common.SuccessCode, bson.M{"token": sessionID, "type": "account"})
}

// Logout handles user logout
func Logout(c *gin.Context) {
	token := c.GetHeader("token")
	if token == "" {
		common.Response(c, common.ErrorCode, "token is required")
		return
	}

	if err := redis.RedisProxyImpl.Client.Del(context.Background(), token).Err(); err != nil {
		common.Response(c, common.ErrorCode, "logout error: "+err.Error())
		return
	}
	common.Response(c, common.SuccessCode, nil)
}

// Regist handles user registration
func Regist(c *gin.Context) {
	var user mongo.User
	if err := c.BindJSON(&user); err != nil {
		common.Response(c, common.ErrorCode, "invalid request: "+err.Error())
		return
	}

	// Prevent users from registering as admin
	if user.Role == mongo.RoleAdmin {
		user.Role = mongo.RoleReadWrite
	}

	if err := mongo.CreateUser(user.Username, user.Password, user.Role); err != nil {
		common.Response(c, common.ErrorCode, "registration error: "+err.Error())
		return
	}
	common.Response(c, common.SuccessCode, nil)
}

type CurrentUserResp struct {
	Name string `json:"name"`
}

// CurrentUser retrieves the current logged-in user's information
func CurrentUser(c *gin.Context) {
	token := c.GetHeader("token")
	if token == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	username, err := redis.RedisProxyImpl.Client.Get(context.Background(), token).Result()
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if username == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	common.Response(c, common.SuccessCode, CurrentUserResp{Name: username})
}
