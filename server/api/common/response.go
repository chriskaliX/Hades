package common

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type StatusCode int

const (
	SuccessCode = iota
	ErrorCode
	AuthFailureCode
)

func Response(c *gin.Context, code StatusCode, message interface{}) {
	switch code {
	case SuccessCode:
		c.IndentedJSON(
			http.StatusOK, gin.H{
				"code":    code,
				"data":    message,
				"message": "",
			},
		)
	default:
		c.IndentedJSON(
			http.StatusOK, gin.H{
				"code":    code,
				"data":    "",
				"message": message,
			},
		)
	}
}
