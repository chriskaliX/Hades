package user

import (
	"hboat/pkg/api/common"
	"hboat/pkg/datasource/mongo"
	iuser "hboat/pkg/internal/user"

	"github.com/gin-gonic/gin"
)

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
	if err := iuser.CreateUser(user.Username, user.Password, user.Role); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	common.Response(c, common.SuccessCode, nil)
}
