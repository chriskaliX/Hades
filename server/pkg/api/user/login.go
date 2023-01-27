package user

import (
	"hboat/pkg/api/common"
	"hboat/pkg/datasource/mongo"

	iuser "hboat/pkg/internal/user"

	"github.com/gin-gonic/gin"
)

func Login(c *gin.Context) {
	// get username
	var user mongo.User
	if err := c.BindJSON(&user); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	// only get username and password
	if err := iuser.CheckPassword(user.Username, user.Password); err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
}
