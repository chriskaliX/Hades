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

// request binding
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Login(c *gin.Context) {
	// get username
	var req LoginRequest
	if err := c.BindJSON(&req); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	// only get username and password
	if err := mongo.CheckPassword(req.Username, req.Password); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	// success, set the session
	sessionid := utils.GenerateSession()
	duration := time.Duration(conf.Config.Backend.UserSessionLifetimeMin) * time.Minute
	if err := redis.RedisProxyImpl.Client.Set(context.Background(), sessionid, req.Username, duration).Err(); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	common.LogRecord(c, fmt.Sprintf("user %s login successfully", req.Username))
	// response with the token
	common.Response(c, common.SuccessCode, bson.M{"token": sessionid})
}

func Logout(c *gin.Context) {
	token := c.GetHeader("token")
	err := redis.RedisProxyImpl.Client.Del(context.Background(), token).Err()
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	common.Response(c, common.SuccessCode, nil)
}

func Regist(c *gin.Context) {
	// get username
	var user mongo.User
	if err := c.BindJSON(&user); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	// admin can not be set by regist
	if user.Role == mongo.RoleAdmin {
		user.Role = mongo.RoleReadWrite
	}
	if err := mongo.CreateUser(user.Username, user.Password, user.Role); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	common.Response(c, common.SuccessCode, nil)
}

type CurrentUserResp struct {
	Name string `json:"name"`
}

func CurrentUser(c *gin.Context) {
	token := c.GetHeader("token")
	if token == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	s := redis.RedisProxyImpl.Client.Get(context.Background(), token)
	if s.Err() != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	username := s.Val()
	if username == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	common.Response(c, common.SuccessCode, CurrentUserResp{
		Name: username,
	})
}
